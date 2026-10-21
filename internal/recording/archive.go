package recording

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ArchiveSnapshot is the portable traffic subset embedded in one task archive.
// Large content-addressed bodies are copied alongside this manifest rather than
// base64-encoded, preserving deduplication and allowing the tar writer to stream.
type ArchiveSnapshot struct {
	Version   int               `json:"version"`
	Exchanges []ArchiveExchange `json:"exchanges"`
	Blobs     []string          `json:"blobs"`
}

type ArchiveExchange struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	ReqLen      int    `json:"req_len"`
	RespLen     int    `json:"resp_len"`
	ReqHead     string `json:"req_head"`
	ReqBody     []byte `json:"req_body,omitempty"`
	ReqBlob     string `json:"req_blob,omitempty"`
	RespHead    string `json:"resp_head"`
	RespBody    []byte `json:"resp_body,omitempty"`
	RespBlob    string `json:"resp_blob,omitempty"`
}

// exportPageRows bounds how many exchanges one read transaction covers. Reading a
// page at a time keeps two things out of a large export: a read transaction open
// for its whole duration, which would pin the WAL against checkpointing, and the
// traffic write lock, which record() waits on before go-mitmproxy answers a client
// — an archive of a busy task used to freeze capture for as long as it ran.
const exportPageRows = 2000

// ExportHosts writes an exact-host snapshot to dir. Rows are read in bounded pages,
// each page in its own read transaction, so every exchange is paired with the
// bodies that belong to it in one consistent view while the recorder keeps
// running. The content-addressed blobs those bodies point at are copied before the
// purge that follows can collect them: as long as the rows being exported exist,
// their blobs are referenced.
func (t *Traffic) ExportHosts(hosts []string, dir string) (int64, error) {
	if t == nil || len(hosts) == 0 {
		return 0, nil
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return 0, err
	}
	unique := uniqueArchiveHosts(hosts)
	placeholders := make([]string, len(unique))
	args := make([]any, len(unique))
	for i, host := range unique {
		placeholders[i] = "?"
		args[i] = host
	}
	snapshot := ArchiveSnapshot{Version: 1}
	blobs := map[string]struct{}{}
	var lastTS int64
	var lastID string
	hasCursor := false
	for {
		page, cursorTS, cursorID, err := t.exportHostPage(placeholders, args, hasCursor, lastTS, lastID, &snapshot, blobs)
		if err != nil {
			return 0, err
		}
		if page == 0 {
			break
		}
		lastTS, lastID, hasCursor = cursorTS, cursorID, true
	}
	report, err := t.writeArchive(dir, &snapshot, blobs)
	if err != nil {
		return 0, err
	}
	return int64(report.Exchanges), nil
}

// ExportReport summarises one export: how many exchanges were written and how many
// bytes the archive occupies on disk (manifest plus the blob copies).
type ExportReport struct {
	Exchanges int      `json:"exchanges"`
	Bytes     int64    `json:"bytes"`
	Truncated bool     `json:"truncated"`
	Files     []string `json:"files"`
}

// writeArchive materialises a snapshot as the on-disk layout ImportArchive reads:
// recording.json plus one blobs/<sha256>.bin per content-addressed body. It is shared
// by the host-scoped export used by task archives and by the time-window export the
// sandbox serves, so both produce archives the same importer accepts.
func (t *Traffic) writeArchive(dir string, snapshot *ArchiveSnapshot, blobs map[string]struct{}) (*ExportReport, error) {
	report := &ExportReport{}
	hashes := make([]string, 0, len(blobs))
	for hash := range blobs {
		hashes = append(hashes, hash)
	}
	sort.Strings(hashes)
	for _, hash := range hashes {
		source, err := t.blobPath(hash)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(dir, "blobs", hash+".bin"), data, 0o600); err != nil {
			return nil, err
		}
		report.Bytes += int64(len(data))
		report.Files = append(report.Files, "blobs/"+hash+".bin")
		snapshot.Blobs = append(snapshot.Blobs, hash)
	}
	sort.Strings(snapshot.Blobs)
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "recording.json"), raw, 0o600); err != nil {
		return nil, err
	}
	report.Exchanges = len(snapshot.Exchanges)
	report.Bytes += int64(len(raw))
	report.Files = append(report.Files, "recording.json")
	sort.Strings(report.Files)
	return report, nil
}

// ExportRange writes every exchange recorded in [since, until] (unix seconds,
// inclusive) to dir, newest first, stopping after limit rows. The layout is exactly
// what ImportArchive reads, so a sandbox can export and the control plane can
// import without a second format.
//
// Newest first is what makes a bounded export useful: with a limit the caller wants
// the most recent recording. Rows are read in exportPageRows pages with a descending
// (ts,id) keyset cursor, so no read transaction spans the whole export and capture
// keeps running. limit <= 0 means "every matching row".
func (t *Traffic) ExportRange(since, until int64, limit int, dir string) (*ExportReport, error) {
	if t == nil {
		return nil, errors.New("traffic: nil store")
	}
	if until <= 0 {
		until = math.MaxInt64
	}
	if since > until {
		return nil, fmt.Errorf("时间范围非法: since(%d) > until(%d)", since, until)
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	snapshot := ArchiveSnapshot{Version: 1}
	blobs := map[string]struct{}{}
	var lastTS int64
	var lastID string
	hasCursor := false
	for {
		pageLimit := exportPageRows
		if limit > 0 {
			remaining := limit - len(snapshot.Exchanges)
			if remaining <= 0 {
				break
			}
			if remaining < pageLimit {
				pageLimit = remaining
			}
		}
		page, cursorTS, cursorID, err := t.exportRangePage(since, until, hasCursor, lastTS, lastID, pageLimit, &snapshot, blobs)
		if err != nil {
			return nil, err
		}
		if page == 0 {
			break
		}
		lastTS, lastID, hasCursor = cursorTS, cursorID, true
	}
	report, err := t.writeArchive(dir, &snapshot, blobs)
	if err != nil {
		return nil, err
	}
	if limit > 0 && hasCursor {
		more, err := t.rangeHasMore(since, until, lastTS, lastID)
		if err != nil {
			return nil, err
		}
		report.Truncated = more
	}
	return report, nil
}

// exportRangePage reads one newest-first page of a range export. The keyset cursor
// keeps (ts,id) descending order stable across pages without holding a transaction
// open longer than one page.
func (t *Traffic) exportRangePage(
	since, until int64, hasCursor bool, lastTS int64, lastID string, pageLimit int,
	snapshot *ArchiveSnapshot, blobs map[string]struct{},
) (page int, cursorTS int64, cursorID string, err error) {
	ctx := context.Background()
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, "", err
	}
	defer tx.Rollback() //nolint:errcheck // read-only

	query := `SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path
FROM exchanges WHERE ts >= ? AND ts <= ?`
	queryArgs := make([]any, 0, 4)
	queryArgs = append(queryArgs, since, until)
	if hasCursor {
		query += ` AND (ts,id) < (?,?)`
		queryArgs = append(queryArgs, lastTS, lastID)
	}
	query += ` ORDER BY ts DESC,id DESC LIMIT ?`
	queryArgs = append(queryArgs, pageLimit)

	rows, err := tx.Query(query, queryArgs...)
	if err != nil {
		return 0, 0, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var item ArchiveExchange
		var legacyPath string
		if err := rows.Scan(&item.ID, &item.TS, &item.Host, &item.Method, &item.URLTemplate,
			&item.URL, &item.Status, &item.ContentType, &item.ReqLen, &item.RespLen, &legacyPath); err != nil {
			return 0, 0, "", err
		}
		if err := t.readArchiveBodies(tx, &item, legacyPath); err != nil {
			return 0, 0, "", err
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				blobs[hash] = struct{}{}
			}
		}
		snapshot.Exchanges = append(snapshot.Exchanges, item)
		lastTS, lastID = item.TS, item.ID
		page++
	}
	if err := rows.Err(); err != nil {
		return 0, 0, "", err
	}
	return page, lastTS, lastID, nil
}

// rangeHasMore reports whether the range still holds a row older than the cursor.
// It is what separates "the export stopped exactly at limit" from "rows were cut".
func (t *Traffic) rangeHasMore(since, until, lastTS int64, lastID string) (bool, error) {
	var one int
	err := t.db.QueryRow(`SELECT 1 FROM exchanges WHERE ts >= ? AND ts <= ? AND (ts,id) < (?,?) LIMIT 1`,
		since, until, lastTS, lastID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// readArchiveBodies fills the request/response side of one exchange, including the
// legacy per-directory request.http/response.http fallback old installs still have.
// Both export paths share it so host-scoped and time-window archives cannot drift.
func (t *Traffic) readArchiveBodies(tx *sql.Tx, item *ArchiveExchange, legacyPath string) error {
	var reqBlob, respBlob sql.NullString
	err := tx.QueryRow(`SELECT req_head,req_body,req_blob,resp_head,resp_body,resp_blob
FROM exchange_bodies WHERE id=?`, item.ID).Scan(&item.ReqHead, &item.ReqBody, &reqBlob, &item.RespHead, &item.RespBody, &respBlob)
	if errors.Is(err, sql.ErrNoRows) && strings.TrimSpace(legacyPath) != "" {
		req, readErr := os.ReadFile(filepath.Join(t.dir, legacyPath, "request.http"))
		if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
		resp, readErr := os.ReadFile(filepath.Join(t.dir, legacyPath, "response.http"))
		if readErr != nil && !os.IsNotExist(readErr) {
			return readErr
		}
		item.ReqHead, item.RespHead = string(req), string(resp)
	} else if err != nil {
		return err
	}
	item.ReqBlob, item.RespBlob = reqBlob.String, respBlob.String
	return nil
}

// ArchiveCoverage reports how many exchanges recorded in an archive directory are
// present in this store, matched by primary key. The control plane uses it as the
// post-import check before deleting the node-side copy: the node's own recorder
// still holds the rows, so deletion is only safe once every archived row is here.
func (t *Traffic) ArchiveCoverage(dir string) (present, total int, err error) {
	raw, err := os.ReadFile(filepath.Join(dir, "recording.json"))
	if err != nil {
		return 0, 0, err
	}
	var snapshot ArchiveSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return 0, 0, err
	}
	ids := make([]string, 0, len(snapshot.Exchanges))
	seen := make(map[string]struct{}, len(snapshot.Exchanges))
	for _, item := range snapshot.Exchanges {
		if _, dup := seen[item.ID]; dup {
			continue
		}
		seen[item.ID] = struct{}{}
		ids = append(ids, item.ID)
	}
	const coverageChunk = 500
	for start := 0; start < len(ids); start += coverageChunk {
		end := min(start+coverageChunk, len(ids))
		placeholders := strings.TrimSuffix(strings.Repeat("?,", end-start), ",")
		args := make([]any, 0, end-start)
		for _, id := range ids[start:end] {
			args = append(args, id)
		}
		rows, err := t.db.Query(`SELECT id FROM exchanges WHERE id IN (`+placeholders+`)`, args...)
		if err != nil {
			return present, len(ids), err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return present, len(ids), err
			}
			present++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return present, len(ids), err
		}
		rows.Close()
	}
	return present, len(ids), nil
}

// exportHostPage reads up to exportPageRows exchanges for the given hosts, in
// (ts,id) order, appending them to snapshot and registering their blob hashes.
// The keyset cursor keeps that order stable across pages without ever holding a
// transaction open longer than one page.
func (t *Traffic) exportHostPage(
	placeholders []string, args []any, hasCursor bool, lastTS int64, lastID string,
	snapshot *ArchiveSnapshot, blobs map[string]struct{},
) (page int, cursorTS int64, cursorID string, err error) {
	ctx := context.Background()
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, "", err
	}
	defer tx.Rollback() //nolint:errcheck // read-only

	query := `SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path
FROM exchanges WHERE host IN (` + strings.Join(placeholders, ",") + `)`
	queryArgs := make([]any, 0, len(args)+3)
	queryArgs = append(queryArgs, args...)
	if hasCursor {
		query += ` AND (ts,id) > (?,?)`
		queryArgs = append(queryArgs, lastTS, lastID)
	}
	query += ` ORDER BY ts,id LIMIT ?`
	queryArgs = append(queryArgs, exportPageRows)

	rows, err := tx.Query(query, queryArgs...)
	if err != nil {
		return 0, 0, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var item ArchiveExchange
		var legacyPath string
		if err := rows.Scan(&item.ID, &item.TS, &item.Host, &item.Method, &item.URLTemplate,
			&item.URL, &item.Status, &item.ContentType, &item.ReqLen, &item.RespLen, &legacyPath); err != nil {
			return 0, 0, "", err
		}
		if err := t.readArchiveBodies(tx, &item, legacyPath); err != nil {
			return 0, 0, "", err
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				blobs[hash] = struct{}{}
			}
		}
		snapshot.Exchanges = append(snapshot.Exchanges, item)
		lastTS, lastID = item.TS, item.ID
		page++
	}
	if err := rows.Err(); err != nil {
		return 0, 0, "", err
	}
	return page, lastTS, lastID, nil
}

// importBatchRows bounds one locked import batch: enough rows that a restore is
// not dominated by per-batch overhead, few enough that one hold of the traffic
// write lock stays short while recording continues.
// 批越小，持有写锁的时间越短；服务进程同时在录制时不会整段饿死。
const importBatchRows = 200

// ImportArchive imports only missing exchange IDs. Current hot rows always win,
// and repeated restore attempts are safe after a partial external failure — which
// is what makes the import safe to run in batches: a restore of a large task used
// to insert every row in one transaction under the traffic write lock, freezing
// capture for as long as the restore took.
func (t *Traffic) ImportArchive(dir string) (int64, error) {
	if t == nil {
		return 0, nil
	}
	raw, err := os.ReadFile(filepath.Join(dir, "recording.json"))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var snapshot ArchiveSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return 0, err
	}
	if snapshot.Version != 1 {
		return 0, fmt.Errorf("unsupported traffic archive version %d", snapshot.Version)
	}
	var imported int64
	for start := 0; start < len(snapshot.Exchanges); start += importBatchRows {
		end := min(start+importBatchRows, len(snapshot.Exchanges))
		n, err := t.importExchangeBatch(dir, snapshot.Exchanges[start:end])
		imported += n
		if err != nil {
			return imported, err
		}
		// 让一次：录制器是实时的，导入是批量的，谁的延迟更贵很清楚。
		time.Sleep(20 * time.Millisecond)
	}
	return imported, nil
}

// importExchangeBatch installs one batch of archived exchanges: the blobs they
// reference, then their rows, bodies, references and full-text entries, all in one
// transaction under one hold of the write lock. The blob copies belong inside that
// hold: a blob with no reference yet is exactly what gcBlobs collects, so writing
// one outside it would let collection delete a body the batch is about to point at.
func (t *Traffic) importExchangeBatch(dir string, batch []ArchiveExchange) (int64, error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()

	verified := make(map[string]struct{}, len(batch))
	for _, item := range batch {
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash == "" {
				continue
			}
			if _, done := verified[hash]; done {
				continue
			}
			verified[hash] = struct{}{}
			if err := t.installArchivedBlob(dir, hash); err != nil {
				return 0, err
			}
		}
	}

	tx, err := t.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var imported int64
	for _, item := range batch {
		res, err := tx.Exec(`INSERT OR IGNORE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`, item.ID, item.TS, item.Host, item.Method, item.URLTemplate,
			item.URL, item.Status, item.ContentType, item.ReqLen, item.RespLen)
		if err != nil {
			return imported, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, item.ID, item.ReqHead, item.ReqBody, nullIfEmpty(item.ReqBlob),
			item.RespHead, item.RespBody, nullIfEmpty(item.RespBlob)); err != nil {
			return imported, err
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, hash, item.ID); err != nil {
					return imported, err
				}
			}
		}
		if t.fts {
			var rowID int64
			if err := tx.QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, item.ID).Scan(&rowID); err != nil {
				return imported, err
			}
			content := strings.Join([]string{item.URL, item.ReqHead, string(item.ReqBody), item.RespHead, string(item.RespBody)}, "\n")
			if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowID, content); err != nil {
				return imported, err
			}
		}
		imported++
	}
	if err := tx.Commit(); err != nil {
		return imported, err
	}
	return imported, nil
}

// installArchivedBlob verifies one archived blob against its own hash and copies
// it into the store when it is not there yet. Blobs are content-addressed, so the
// hash both names the file and proves the bytes.
func (t *Traffic) installArchivedBlob(dir, hash string) error {
	if !blobHashRe.MatchString(hash) {
		return fmt.Errorf("invalid archived traffic blob %q", hash)
	}
	data, err := os.ReadFile(filepath.Join(dir, "blobs", hash+".bin"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != hash {
		return fmt.Errorf("traffic blob checksum mismatch: %s", hash)
	}
	destination := filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin")
	if _, err := os.Stat(destination); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(destination, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func uniqueArchiveHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
