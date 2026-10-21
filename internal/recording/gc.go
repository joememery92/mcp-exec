package recording

import (
	"context"
	"fmt"
	"time"
)

// CountBefore reports how many exchanges are older than cutoff and how many
// response bytes they claim. It is the read-only half of a retention sweep: the
// UI's "what would this delete" and 预演模式 both need it, and it
// must not touch anything, so it runs under the read lock only.
func (t *Traffic) CountBefore(cutoff time.Time) (exchanges int64, respBytes int64, err error) {
	row := t.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(resp_len), 0) FROM exchanges WHERE ts < ?`, cutoff.Unix())
	if err := row.Scan(&exchanges, &respBytes); err != nil {
		return 0, 0, fmt.Errorf("统计过期流量: %w", err)
	}
	return exchanges, respBytes, nil
}

// OldestTimestamp reports the recording time of the earliest exchange, or zero
// when the index is empty. Retention decisions are easier to explain when the
// displayed range is the real one instead of an assumed window.
func (t *Traffic) OldestTimestamp() (time.Time, error) {
	var ts *int64
	if err := t.db.QueryRow(`SELECT MIN(ts) FROM exchanges`).Scan(&ts); err != nil {
		return time.Time{}, fmt.Errorf("读取最早流量时间: %w", err)
	}
	if ts == nil {
		return time.Time{}, nil
	}
	return time.Unix(*ts, 0), nil
}

// DeleteBefore removes every exchange recorded before cutoff.
//
// It reuses the staged purge the host filter already relies on, so the row
// batches, the blob garbage collection and the incremental vacuum are the same
// code path that a UI-triggered deletion takes. What differs is only how the
// row set is chosen (by age rather than by host) and that no journal is written:
// a retention sweep may be interrupted and simply re-run, whereas a host purge
// is tied to an archive the recovery path has to reconcile.
//
// Bodies bound to a finding already live in the evidence store, so deleting
// recorded traffic never takes proof with it.
func (t *Traffic) DeleteBefore(cutoff time.Time) (int64, error) {
	t.wmu.Lock()
	rowids, err := scanRowIDs(t.db, `SELECT rowid FROM exchanges WHERE ts < ?`, cutoff.Unix())
	t.wmu.Unlock()
	if err != nil {
		return 0, fmt.Errorf("列出过期流量: %w", err)
	}
	if len(rowids) == 0 {
		return 0, nil
	}
	stage := &HostDeleteStage{
		traffic: t,
		journal: hostDeleteStageJournal{Version: 2, Phase: hostDeletePhaseStaged},
		rowids:  rowids,
		deleted: int64(len(rowids)),
	}
	if err := stage.Commit(); err != nil {
		return 0, err
	}
	return stage.Deleted(), nil
}

// ReclaimToCompletion runs the incremental vacuum and the full-text merges until
// neither makes progress, ignoring the budget reclaim() applies to background
// work. A retention sweep is an explicit, user-visible operation: it should hand
// the disk back before the command returns, not leave the rest to "next delete".
//
// The vacuum is the expensive half (it rewrites pages the deletion freed), so the
// caller decides when to pay for it; ctx bounds an interactive invocation.
func (t *Traffic) ReclaimToCompletion(ctx context.Context) error {
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("获取索引连接: %w", err)
	}
	defer conn.Close()

	merges := reclaimMergeSteps
	for {
		t.wmu.Lock()
		progressed, err := t.reclaimChunk(ctx, conn, &merges)
		t.wmu.Unlock()
		if err != nil {
			return err
		}
		if !progressed {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	// Truncating the log is what makes the result visible on disk: in WAL mode the
	// freed pages are recorded there first, and PASSIVE would leave the log at its
	// high-water mark.
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("截断 WAL: %w", err)
	}
	return nil
}

// IndexSize reports the index and WAL size on disk, which is what a retention
// report has to quote: the exchange table's own footprint is not the disk bill.
func (t *Traffic) IndexSize() int64 { return t.indexBytes() }
