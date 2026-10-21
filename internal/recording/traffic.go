// Package traffic implements the request-recording subsystem (docs §10): an
// embedded go-mitmproxy proxy whose addon writes every target HTTP exchange into
// a human-browsable file tree, with a sidecar SQLite index for paged queries.
// Full capture, plaintext (no redaction), target HTTP only.
package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	mproxy "github.com/lqqyt2423/go-mitmproxy/proxy"
	_ "modernc.org/sqlite"
)

const indexSchema = `
CREATE TABLE IF NOT EXISTS exchanges (
  id           TEXT PRIMARY KEY,
  ts           INTEGER,
  host         TEXT,
  method       TEXT,
  url_template TEXT,
  url          TEXT,
  status       INTEGER,
  content_type TEXT,
  req_len      INTEGER,
  resp_len     INTEGER,
  path         TEXT
);
CREATE INDEX IF NOT EXISTS idx_ex_host ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_ex_tmpl ON exchanges(host, url_template);
CREATE INDEX IF NOT EXISTS idx_ex_ts   ON exchanges(ts);
CREATE INDEX IF NOT EXISTS idx_ex_status ON exchanges(status);
CREATE INDEX IF NOT EXISTS idx_ex_resp   ON exchanges(resp_len);

CREATE TABLE IF NOT EXISTS exchange_bodies (
  id        TEXT PRIMARY KEY,
  req_head  TEXT NOT NULL DEFAULT '',
  req_body  BLOB,
  req_blob  TEXT,
  resp_head TEXT NOT NULL DEFAULT '',
  resp_body BLOB,
  resp_blob TEXT
);

CREATE TABLE IF NOT EXISTS blob_refs (
  hash        TEXT NOT NULL,
  exchange_id TEXT NOT NULL,
  PRIMARY KEY (hash, exchange_id)
);
CREATE INDEX IF NOT EXISTS idx_blob_refs_ex ON blob_refs(exchange_id);
`

// ftsSchema is applied separately from indexSchema: a driver build without FTS5
// must degrade to "no full-text search" rather than take the whole recorder down.
// trigram (not the default unicode61) is required for two reasons this subsystem
// depends on: it matches arbitrary substrings — "ssw0r" finds "P@ssw0rd" — and it
// handles CJK, which unicode61 does not tokenize. Contentless (content=”) keeps
// only the index, since the text itself lives in exchange_bodies; contentless_delete
// lets rows be deleted without replaying the original text back in.
const ftsSchema = `CREATE VIRTUAL TABLE IF NOT EXISTS ex_fts USING fts5(
  content, tokenize='trigram', content='', contentless_delete=1
);`

const (
	// maxInlineBody is the cutoff between a body stored inline (SQLite column) and
	// one spilled to the content-addressed blob store.
	maxInlineBody = 256 * 1024
	// blobPreview is how much of a spilled body stays inline so readers can tell
	// what it is (JSON shape, SQL dump header, ZIP magic) without fetching it.
	blobPreview = 8 * 1024
	// maxIndexBody caps a single body's contribution to the full-text index. Text
	// is indexed in full below this; binary never reaches the index at all.
	maxIndexBody = 4 * 1024 * 1024
	// minTrigram is the shortest term the trigram tokenizer can match; shorter
	// queries fall back to metadata LIKE.
	minTrigram = 3
	// maxBlobRead caps one traffic_blob read so paging through a large body never
	// floods the agent's context.
	maxBlobRead = 8 * 1024
	// autoVacuumIncremental is SQLite's numeric value for auto_vacuum=incremental.
	autoVacuumIncremental = 2
	// ftsAutoMergeSegments is fts5's documented default for how many segments must
	// accumulate before write-time merging kicks in. It is named because startup
	// restores it: a suspended merge during a purge must not outlive the process.
	ftsAutoMergeSegments = 4
	// reclaimChunkPages bounds how much index space one locked step returns to the
	// filesystem (pages are 4KiB, so ~32MB). Reclamation holds the write lock, and
	// record() runs before go-mitmproxy replies to the client, so an unbounded
	// pass would stall the very requests being recorded.
	reclaimChunkPages = 8192
	// reclaimMergePages bounds the full-text merge done alongside each chunk.
	// Deleting from a contentless_delete index only writes tombstones; merging is
	// what discards them, and left undone the index grows on every deletion.
	reclaimMergePages = 256
	// reclaimMergeSteps bounds how many merges one reclamation performs. fts5
	// offers no way to ask whether an index has settled — its special INSERT
	// registers a row change of its own, so change counting cannot tell a real
	// merge from a no-op — so the budget is simply spent down, and whatever is
	// left over falls to the next deletion.
	reclaimMergeSteps = 16
	// reclaimMaxSteps backstops the loop. Both merging and incremental_vacuum are
	// documented to stop making progress eventually, but a reclamation that cannot
	// converge must give up rather than spin holding the write lock.
	reclaimMaxSteps = 512
	// reclaimBudget caps one background reclamation. Deleting a busy host can free
	// gigabytes, and the next deletion resumes wherever this one stopped.
	reclaimBudget = 5 * time.Minute
	// deleteBatchInitialRows, deleteBatchMinRows and deleteBatchMaxRows bound how
	// many exchange rows one purge transaction removes, and
	// deleteBatchHoldBudget is the write-lock hold a purge aims to stay under.
	//
	// A purge has to be split across commits: SQLite has a single writer, so
	// releasing the traffic write lock in the middle of one open transaction would
	// only move the stall onto SQLite's own busy timeout, and the write lock is
	// what record() waits on before go-mitmproxy answers the client. How long a
	// batch takes depends on the host, not on the row count — deleting from a
	// contentless_delete full-text index writes a tombstone and rebalances a
	// b-tree per row, at random reads, and the measured per-row cost ranges from
	// under a millisecond to tens of them — so the size is adjusted from what each
	// batch actually cost rather than fixed. Measured on the 2026-10-19 benchmark
	// (20,000 full-text-heavy exchanges), a fixed 128-row batch held the lock for
	// up to 3.9s; adapting settles near the budget while a cheap purge still moves
	// 1024 rows per commit.
	deleteBatchInitialRows = 128
	deleteBatchMinRows     = 16
	deleteBatchMaxRows     = 1024
	deleteBatchHoldBudget  = 500 * time.Millisecond
)

// Journal phases of a staged host purge. "staged" means nothing has been deleted
// yet: the rows to remove are recorded and the legacy trees are moved aside, and
// the whole purge is still reversible. "deleting" means the purge is committed —
// a process exit from here on must finish the deletion, never restore trees over
// rows that are already gone.
const (
	hostDeletePhaseStaged   = "staged"
	hostDeletePhaseDeleting = "deleting"
)

// TrafficSearchDescription is persisted into the tool catalog for new and
// upgraded installations. Keep it in the traffic package so the runtime tool
// and the catalog migration cannot drift apart.
const TrafficSearchDescription = "查询记录代理已抓取的目标流量（必须指定 host；支持裸主机、主机:端口或完整 URL，可再按 URL 子串或正文关键词过滤）。指定端口时只返回该服务的流量，避免同一 IP 的不同端口串包。body_contains 会在已抓取的请求/响应头与正文中做全文搜索，支持任意子串和中文（至少 3 个字符）。仅返回极轻量索引(id/method/url/status/resp_len)，不含响应内容；结果非空后必须用 traffic_get 逐条核实请求/响应，再把确实支持当前漏洞的 ID 交给 bind_finding_traffic。默认只返回 3 条、每页最多 10 条；结果多时用 page 翻页。"

// Traffic runs the recording proxy and owns the file tree + index.
type Traffic struct {
	dir   string
	addr  string
	db    *sql.DB
	wmu   sync.Mutex // serializes record() vs DeleteHost (incl. blob GC)
	seq   atomic.Int64
	proxy *mproxy.Proxy
	// fts reports whether the full-text index is available. False on a driver
	// build without FTS5: recording and metadata search still work, body search
	// degrades to unsupported rather than erroring.
	fts bool
	// reaping tracks background reclamation of legacy trees and index space, so
	// shutdown and tests can wait for it instead of racing it.
	reaping sync.WaitGroup
	// incrementalVacuum reports whether the index can return freed pages to the
	// filesystem on its own. False on a database created before this was the
	// default: PRAGMA incremental_vacuum is a silent no-op there, so deletions
	// reclaim nothing until an explicit full compaction converts the file.
	incrementalVacuum bool
	// reclaiming keeps a single background reclamation in flight. Concurrent ones
	// would only contend for wmu, never finish sooner.
	reclaiming atomic.Bool
	// closed is shut by Close so a reclamation abandons its remaining budget
	// instead of holding shutdown open for minutes. Nil on the zero value, which
	// stopping() treats as "not closing".
	closed    chan struct{}
	closeOnce sync.Once
	// pass is the set of hosts whose MITM interception failed for a proxy/protocol
	// reason; connections to them are tunneled transparently (fail-open) so the
	// request still reaches the target — unrecorded — instead of being killed.
	pass sync.Map // hostname(string) -> struct{}
	// upstream is the global egress proxy every captured request is forwarded
	// through (nil = dial targets directly). Both the intercepted and the
	// transparent-passthrough paths honor it (go-mitmproxy's getUpstreamConn),
	// so no host escapes it. Hot-swappable at runtime via SetUpstreamProxy.
	upstream atomic.Pointer[url.URL]
	// uaProvider, when set, returns the UA the platform's own fetches (norma
	// WebFetch, which hardcodes its UA) must present for a host. Installed once at
	// startup via SetUAProvider (see ua_override.go); a nil/unloaded value leaves
	// every request's UA untouched.
	uaProvider atomic.Value // func(host string) string
}

// Open initializes the traffic tree, blob store and SQLite index under dir.
func Open(dir, addr string) (*Traffic, error) {
	for _, d := range []string{dir, filepath.Join(dir, "_index"), filepath.Join(dir, "_blobs"), filepath.Join(dir, "_ca")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, err
		}
	}
	// busy_timeout is a per-connection setting, so it belongs in the DSN rather
	// than in a one-off Exec: the pool opens connections on demand, and an Exec
	// only configures whichever one happened to serve it — leaving every other
	// connection to fail instantly the moment a writer holds the database.
	// The driver splits the DSN at the first '?', so a data directory containing
	// one would silently name a different file; that path falls back to a bare
	// DSN, where initIndex still applies the pragmas to its own connection.
	index := filepath.Join(dir, "_index", "index.sqlite")
	dsn := index
	if !strings.ContainsRune(index, '?') {
		dsn = "file:" + index + "?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	t := &Traffic{dir: dir, addr: addr, db: db, closed: make(chan struct{})}
	if err := t.initIndex(); err != nil {
		db.Close()
		return nil, err
	}

	p, err := mproxy.NewProxy(&mproxy.Options{
		Addr:        addr,
		SslInsecure: true,
		CaRootPath:  filepath.Join(dir, "_ca"),
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	// Upstream selection. By default (no global egress proxy set) targets are
	// dialed DIRECTLY: go-mitmproxy's own default upstream uses
	// http.ProxyFromEnvironment, so an HTTP_PROXY/HTTPS_PROXY in the environment
	// (a VPN/system proxy) would make it forward target requests through that
	// external proxy — which can't reach the target → 502. Returning nil forces
	// a direct dial. When a global egress proxy IS configured (SetUpstreamProxy),
	// every captured request — intercepted AND transparently tunneled — is
	// forwarded through it instead, so no host leaks the real source IP.
	p.SetUpstreamProxy(func(*http.Request) (*url.URL, error) { return t.upstream.Load(), nil })
	// Fail-open: MITM every host by default, EXCEPT ones a prior request proved we
	// can't intercept without breaking (see maybePassthrough). Those are tunneled
	// transparently so the request still reaches the target instead of being killed.
	p.SetShouldInterceptRule(func(req *http.Request) bool {
		_, tunnel := t.pass.Load(hostOnly(req.Host))
		return !tunnel
	})
	p.AddAddon(&sink{t: t})
	t.proxy = p
	return t, nil
}

// initIndex applies the schema on a single pinned connection. Pinning is what
// makes auto_vacuum reliable: it can only be set while the database still holds
// no tables, and only the VACUUM that follows writes it into the file header —
// two steps a pooled *sql.DB is free to route to different connections, which
// would silently drop the setting.
//
// auto_vacuum=incremental is what lets a deletion hand freed pages back to the
// filesystem. Without it SQLite merely chains them onto its freelist, so the
// index file never shrinks no matter how much traffic is deleted — and since
// every body below maxInlineBody lives in that file, plus a trigram index
// roughly twice the size of the text it covers, a capture-heavy install ends up
// holding gigabytes for traffic it no longer has. On a database that already has
// tables the pragma is a documented no-op, so installs created before this keep
// auto_vacuum=0 until a full compaction converts the file; incrementalVacuum
// records that so reclaim can say so instead of pretending to reclaim.
func (t *Traffic) initIndex() error {
	ctx := context.Background()
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Re-applied rather than left to the DSN so the bare-DSN fallback in Open is
	// still correct: journal_mode persists in the file header, which is what every
	// later connection reads.
	for _, p := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA busy_timeout=30000`} {
		if _, err := conn.ExecContext(ctx, p); err != nil {
			return err
		}
	}
	var tables int
	if err := conn.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type='table'`).Scan(&tables); err != nil {
		return err
	}
	if tables == 0 {
		for _, p := range []string{`PRAGMA auto_vacuum=incremental`, `VACUUM`} {
			if _, err := conn.ExecContext(ctx, p); err != nil {
				return err
			}
		}
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return err
	}
	t.incrementalVacuum = mode == autoVacuumIncremental
	if !t.incrementalVacuum {
		log.Printf("[traffic] 索引库未启用增量回收（auto_vacuum=%d）：删除流量不会缩小 index.sqlite，需要执行一次存储压缩来转换", mode)
	}
	if _, err := conn.ExecContext(ctx, indexSchema); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, ftsSchema); err != nil {
		log.Printf("[traffic] 全文索引不可用，正文搜索将被禁用（元数据搜索不受影响）：%v", err)
		return nil
	}
	t.fts = true
	// Index-level fts5 settings, enforced on every start so they are the steady
	// state after any suspension (a purge suspends merging for its own duration).
	//
	// fts5 merges a segment as soon as a tenth of its rows are tombstoned
	// ('deletemerge'), and that merge runs inside whichever write transaction
	// crossed the ratio — during a purge that is nearly every commit, because
	// deleting a busy host tombstones most of the index. Measured 2026-10-19, this
	// alone made one 20,000-row purge take 41s instead of 4s and put holds of up to
	// 9.7s on the traffic write lock, which is time record() spends before
	// go-mitmproxy answers a client. Merging is maintenance, not part of a delete:
	// this package already discards tombstones in bounded `merge` steps taken by
	// the background reclamation, between lock holds, resuming where it stopped.
	// Turning the ratio-triggered merge off does not let the index fragment —
	// 'automerge' still merges segments as they are written and 'crisismerge'
	// still caps the segment count — and it applies to existing indexes too, since
	// the setting lives in the index's own config table.
	for _, setting := range []struct {
		name  string
		value int
	}{
		{"deletemerge", 0},
		{"automerge", ftsAutoMergeSegments},
	} {
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts, rank) VALUES(?, ?)`, setting.name, setting.value); err != nil {
			log.Printf("[traffic] 设置全文索引 %s=%d 失败：%v", setting.name, setting.value, err)
		}
	}
	return nil
}

// suspendFTSAutoMerge turns write-time segment merging off for the duration of one
// purge and returns the function that turns it back on. Write-time merging is
// proportional to how many segments the index is holding, so as a purge shrinks the
// index a single merge can run for seconds inside a batch commit: measured
// 2026-10-19 at 200,000 rows, holding the traffic write lock for up to 30s with it
// on versus 7.4s with it off (the reclaim's bounded merge steps still discard the
// tombstones this leaves behind). Setting it is a small write of its own, hence the
// lock.
func (t *Traffic) suspendFTSAutoMerge() func() {
	if t == nil || !t.fts {
		return func() {}
	}
	t.setFTSAutoMerge(0)
	return func() { t.setFTSAutoMerge(ftsAutoMergeSegments) }
}

func (t *Traffic) setFTSAutoMerge(segments int) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if _, err := t.db.Exec(`INSERT INTO ex_fts(ex_fts, rank) VALUES('automerge', ?)`, segments); err != nil {
		log.Printf("[traffic] 设置全文索引 automerge=%d 失败：%v", segments, err)
	}
}

// hostOnly strips an optional :port, so passthrough keys match whether the host
// arrives as "example.com:443" (CONNECT) or "example.com" (request URL).
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// ProxyAddr returns the address workers should set as HTTP(S)_PROXY. A bare
// ":port" means "bind all interfaces" (legacy default), so map it to loopback.
func (t *Traffic) ProxyAddr() string {
	if strings.HasPrefix(t.addr, ":") {
		return "http://127.0.0.1" + t.addr
	}
	return "http://" + t.addr
}

// SetUpstreamProxy points every captured request at a global egress proxy
// (http/https/socks5, optional user:pass in the URL). An empty raw string clears
// it, restoring direct dialing. The change is atomic and takes effect on the next
// connection — no restart, no proxy rebuild. go-mitmproxy dials all three schemes
// itself, so socks5 works uniformly here regardless of the target tool.
func (t *Traffic) SetUpstreamProxy(raw string) error {
	if strings.TrimSpace(raw) == "" {
		t.upstream.Store(nil)
		return nil
	}
	u, err := ValidateProxyURL(raw)
	if err != nil {
		return err
	}
	t.upstream.Store(u)
	return nil
}

// ValidateProxyURL parses and checks a proxy URL (http/https/socks5, optional
// user:pass), returning the parsed URL. Exposed so callers can validate a global
// proxy before persisting it even when the traffic proxy itself is disabled.
func ValidateProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("解析代理地址 %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	case "":
		return nil, fmt.Errorf("代理 %q 缺少协议(用 http://、https:// 或 socks5://)", raw)
	default:
		return nil, fmt.Errorf("不支持的代理协议 %q(用 http、https 或 socks5)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("代理 %q 缺少主机地址", raw)
	}
	return u, nil
}

// CACertPath returns the PEM CA cert clients must trust to verify HTTPS through
// the MITM proxy (go-mitmproxy writes it here on first start).
func (t *Traffic) CACertPath() string {
	return filepath.Join(t.dir, "_ca", "mitmproxy-ca-cert.pem")
}

// Start runs the proxy (blocking); run in a goroutine.
func (t *Traffic) Start() error { return t.proxy.Start() }

// Close waits for background tree reclamation to finish before closing the
// index, so shutdown never leaves a goroutine unlinking files out from under a
// removed data directory. Index-space reclamation is signalled to stop first:
// it holds a whole minutes-long budget, and finishing it is never worth delaying
// shutdown for — the next deletion resumes it.
func (t *Traffic) Close() error {
	if t.closed != nil {
		t.closeOnce.Do(func() { close(t.closed) })
	}
	t.reaping.Wait()
	return t.db.Close()
}

// stopping reports whether Close has been called. A nil channel (the zero value)
// is never ready, so this reads as "not closing" without a separate guard.
func (t *Traffic) stopping() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}
func (t *Traffic) DB() *sql.DB { return t.db }

// sink is the go-mitmproxy addon that records completed exchanges.
type sink struct {
	mproxy.BaseAddon
	t *Traffic
}

func (s *sink) Response(f *mproxy.Flow) {
	if f.Request == nil || f.Response == nil {
		return
	}
	s.t.record(f)
}

// RequestError fires when a request through an established MITM tunnel fails. If
// the failure looks proxy/protocol-caused (h2 quirks, HEAD-with-body, protocol
// errors) — not a plain target-unreachable error — we flag the host for
// transparent passthrough so future requests to it succeed instead of dying.
func (s *sink) RequestError(f *mproxy.Flow, err error) { s.t.maybePassthrough(f, err) }

// maybePassthrough marks a host to be tunneled transparently on the next
// connection, but only for errors the proxy itself caused — a target that is
// simply down/filtered would fail without us too, and must stay MITM'd+recorded.
func (t *Traffic) maybePassthrough(f *mproxy.Flow, err error) {
	if err == nil || f == nil || f.Request == nil || f.Request.URL == nil || !proxyCausedErr(err) {
		return
	}
	host := f.Request.URL.Hostname()
	if host == "" {
		return
	}
	if _, loaded := t.pass.LoadOrStore(host, struct{}{}); !loaded {
		log.Printf("[traffic] 与 %s 的 MITM 出错，改为透传（该 host 后续直连目标、不再记录，但请求照常）：%v", host, err)
	}
}

// proxyCausedErr reports whether err indicates the interception layer (not the
// target) is at fault — HTTP/2 handling, HEAD-with-body, or a protocol violation.
func proxyCausedErr(err error) bool {
	s := strings.ToLower(err.Error())
	for _, p := range []string{"head request", "http2", "http/2", "protocol error", "protocol_error", "malformed"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// record persists one exchange entirely in SQLite: metadata, bodies and the
// full-text index. Nothing is written to a per-request directory — only bodies
// above maxInlineBody spill to the content-addressed blob store.
func (t *Traffic) record(f *mproxy.Flow) {
	// The write lock covers blob + index writes, so DeleteHost (and its blob GC)
	// can run under the same lock without racing a concurrent record.
	t.wmu.Lock()
	defer t.wmu.Unlock()
	host := f.Request.URL.Hostname()
	method := f.Request.Method
	tmpl := templatePath(f.Request.URL.EscapedPath())
	n := t.seq.Add(1)
	now := time.Now()
	id := fmt.Sprintf("%d-%04d", now.Unix(), n%10000)

	ct := f.Response.Header.Get("Content-Type")
	url := f.Request.URL.String()
	reqHead := fmt.Sprintf("%s %s %s\n%s", method, f.Request.URL.RequestURI(), f.Request.Proto, requestHeaderLines(f.Request))
	respHead := fmt.Sprintf("HTTP %d\n%s", f.Response.StatusCode, headerLines(f.Response.Header))
	// Bodies are spilled before the transaction opens: blob writes are filesystem
	// work and must not sit inside the SQLite write lock.
	reqB := t.spill(f.Request.Body, f.Request.Header.Get("Content-Type"))
	respB := t.spill(f.Response.Body, ct)

	// SQLite 只有一个写者：CLI 的导入/GC 与录制器会争同一把锁。瞬时 BUSY 不该丢流量，
	// 所以把整段事务放进重试里（幂等：id 由时间戳+序号决定，INSERT OR REPLACE）。
	var writeErr error
	for attempt := 0; attempt < 5; attempt++ {
		writeErr = t.writeExchange(id, now, host, method, tmpl, url, f.Response.StatusCode, ct,
			len(f.Request.Body), len(f.Response.Body), reqHead, respHead, reqB, respB)
		if writeErr == nil || !isBusyErr(writeErr) {
			break
		}
		time.Sleep(time.Duration(100*(attempt+1)) * time.Millisecond)
	}
	if writeErr != nil {
		log.Printf("[traffic] 记录 %s 失败（写索引，重试后仍失败）: %v", url, writeErr)
	}
}

// writeExchange 一次事务写完索引行、正文与全文索引；返回的错误带阶段名，
// 便于上层区分「锁竞争」与「真错误」。
func (t *Traffic) writeExchange(id string, now time.Time, host, method, tmpl, url string,
	status int, ct string, reqLen, respLen int, reqHead, respHead string,
	reqB, respB storedBody) error {
	tx, err := t.db.Begin()
	if err != nil {
		return fmt.Errorf("开启事务: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	res, err := tx.Exec(`INSERT OR REPLACE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`,
		id, now.Unix(), host, method, tmpl, url, status, ct, reqLen, respLen)
	if err != nil {
		return fmt.Errorf("写索引: %w", err)
	}
	rowid, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("取 rowid: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`,
		id, reqHead, reqB.inline, nullIfEmpty(reqB.hash), respHead, respB.inline, nullIfEmpty(respB.hash)); err != nil {
		return fmt.Errorf("写正文: %w", err)
	}
	for _, h := range []string{reqB.hash, respB.hash} {
		if h == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, h, id); err != nil {
			return fmt.Errorf("登记 blob 引用: %w", err)
		}
	}
	if t.fts {
		// The index is fed from memory, so a body that spilled to _blobs is still
		// fully searchable even though only its preview is stored inline.
		idx := strings.Join([]string{url, reqHead, reqB.index, respHead, respB.index}, "\n")
		if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, idx); err != nil {
			return fmt.Errorf("写全文索引: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交: %w", err)
	}
	return nil
}

// isBusyErr 判断是不是 SQLite 的锁竞争（可重试），而不是数据错误。
func isBusyErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "database is locked") || strings.Contains(s, "SQLITE_BUSY")
}

// storedBody is one body after the inline/spill decision: inline is what goes in
// the SQLite column (the whole body, or a preview when spilled), hash names the
// blob when it spilled, and index is the text handed to FTS (empty for binary).
type storedBody struct {
	inline []byte
	hash   string
	index  string
}

// spill decides where one body lives. Small bodies stay inline. Large ones are
// written to the content-addressed store and keep a readable preview inline so a
// reader can identify them without fetching the blob. Either way, text bodies
// are handed to the full-text index in full (up to maxIndexBody) — indexing is
// independent of where the bytes end up.
func (t *Traffic) spill(body []byte, contentType string) storedBody {
	if len(body) == 0 {
		return storedBody{}
	}
	text := !isBinaryBody(contentType, body)
	indexText := func() string {
		if !text {
			return ""
		}
		return string(clipBytes(body, maxIndexBody))
	}
	if len(body) <= maxInlineBody {
		return storedBody{inline: body, index: indexText()}
	}

	sum := sha256.Sum256(body)
	h := hex.EncodeToString(sum[:])
	// One bucket level (256 buckets) is enough to keep any single directory small;
	// the store only ever holds bodies above maxInlineBody, deduplicated by hash.
	blobDir := filepath.Join(t.dir, "_blobs", "sha256", h[:2])
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		log.Printf("[traffic] 创建 blob 目录失败：%v", err)
		return storedBody{inline: clipBytes(body, blobPreview), index: indexText()}
	}
	blobPath := filepath.Join(blobDir, h+".bin")
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		if err := os.WriteFile(blobPath, body, 0o644); err != nil {
			log.Printf("[traffic] 写 blob %s 失败：%v", h, err)
			return storedBody{inline: clipBytes(body, blobPreview), index: indexText()}
		}
	}
	sb := storedBody{hash: h, index: indexText()}
	if text {
		sb.inline = []byte(truncateUTF8(body, blobPreview))
	} else {
		sb.inline = []byte(binaryTag(contentType, body))
	}
	return sb
}

// binaryTypes are content-type prefixes whose bodies are never worth indexing or
// previewing as text. Anything not listed is treated as text (with a NUL-byte
// check as backstop), so unusual-but-searchable types like application/sql or a
// bare text/* are not silently dropped from the index.
var binaryTypes = []string{
	"image/", "audio/", "video/", "font/",
	"application/octet-stream", "application/zip", "application/gzip",
	"application/x-gzip", "application/x-tar", "application/x-7z-compressed",
	"application/x-rar", "application/pdf", "application/x-msdownload",
	"application/vnd.android.package-archive", "application/java-archive",
	"application/wasm", "application/x-shockwave-flash",
}

func isBinaryBody(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	for _, p := range binaryTypes {
		if strings.HasPrefix(ct, p) {
			return true
		}
	}
	// Backstop for mislabeled or absent content types: real text does not carry
	// NUL bytes, so a NUL in the head of the body means binary regardless.
	return bytes.IndexByte(clipBytes(body, 512), 0) >= 0
}

// binaryTag describes a spilled binary body in one line, including the leading
// magic bytes so a reader can recognize the format without downloading it.
func binaryTag(contentType string, body []byte) string {
	ct := strings.TrimSpace(contentType)
	if ct == "" {
		ct = "application/octet-stream"
	}
	magic := hex.EncodeToString(clipBytes(body, 4))
	return fmt.Sprintf("[binary %s, %d bytes, magic=%s]", ct, len(body), magic)
}

func clipBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// truncateUTF8 cuts b to at most n bytes without splitting a multi-byte rune,
// so a preview never ends in half a CJK character.
func truncateUTF8(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	b = b[:n]
	// A rune is at most 4 bytes, so backing off 3 bytes always finds the boundary
	// (unless the input was already invalid UTF-8, in which case we keep the cut).
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		if r, size := utf8.DecodeLastRune(b); r != utf8.RuneError || size != 1 {
			break
		}
		b = b[:len(b)-1]
	}
	return string(b)
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func headerLines(h map[string][]string) string {
	var b strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// requestHeaderLines restores the HTTP Host header, which net/http stores on
// Request.Host rather than in Header. Keeping it in request.http makes the raw
// capture complete and directly replayable.
func requestHeaderLines(req *mproxy.Request) string {
	headers := req.Header.Clone()
	headers.Del("Host")
	host := req.URL.Host
	if raw := req.Raw(); raw != nil && strings.TrimSpace(raw.Host) != "" {
		host = raw.Host
	}
	var b strings.Builder
	if host = strings.TrimSpace(host); host != "" {
		b.WriteString("Host: ")
		b.WriteString(host)
		b.WriteByte('\n')
	}
	b.WriteString(headerLines(headers))
	return b.String()
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "?", "_", "*", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	out := r.Replace(s)
	if out == "" || out == "_" {
		return "root"
	}
	if len(out) > 120 {
		out = out[:120]
	}
	return out
}

var blobHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// blobPath locates a stored blob. Current writes use one bucket level; blobs
// written before that change used two, so both layouts are probed rather than
// migrated.
func (t *Traffic) blobPath(hash string) (string, error) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	// Validated as pure hex before touching the filesystem, so a crafted hash can
	// never traverse out of the blob directory.
	if !blobHashRe.MatchString(hash) {
		return "", fmt.Errorf("非法的 blob hash")
	}
	for _, p := range []string{
		filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash+".bin"),
		filepath.Join(t.dir, "_blobs", "sha256", hash[:2], hash[2:4], hash+".bin"),
	} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("blob %s 不存在", hash)
}

// Blob opens a spilled body for streaming; the caller must close the file.
// Streaming matters here: the driver exposes no incremental BLOB API, so keeping
// large bodies on disk is what lets them be served without loading them whole.
func (t *Traffic) Blob(hash string) (*os.File, int64, error) {
	p, err := t.blobPath(hash)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

// BlobRange reads at most length bytes of a blob from offset, and reports the
// blob's total size. Used by the agent tool to page through a large body without
// pulling all of it into the model's context.
func (t *Traffic) BlobRange(hash string, offset, length int64) (data []byte, total int64, err error) {
	f, size, err := t.Blob(hash)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	if offset < 0 {
		offset = 0
	}
	if offset >= size {
		return nil, size, nil
	}
	if length <= 0 || offset+length > size {
		length = size - offset
	}
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, size, err
	}
	return buf[:n], size, nil
}

// ExchangeMeta is one row of the index (returned by Search).
type ExchangeMeta struct {
	ID          string `json:"id"`
	TS          int64  `json:"ts"`
	Host        string `json:"host"`
	Method      string `json:"method"`
	URLTemplate string `json:"url_template"`
	URL         string `json:"url"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	RespLen     int    `json:"resp_len"`
	Path        string `json:"path"`
}

// Search returns paged exchange metadata (never bodies).
func (t *Traffic) Search(host string, page, size int) ([]ExchangeMeta, error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	q := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path FROM exchanges`
	args := []any{}
	if host != "" {
		q += ` WHERE host=?`
		args = append(args, host)
	}
	q += ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, size, page*size)
	rows, err := t.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangeMeta
	for rows.Next() {
		var m ExchangeMeta
		if err := rows.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ftsFilter builds the SQL condition restricting rows to those whose indexed
// text matches term. ok is false when full-text search cannot serve the term —
// no FTS index on this build, or fewer than three characters, which the trigram
// tokenizer cannot match — leaving callers to fall back to metadata matching.
func (t *Traffic) ftsFilter(term string) (cond string, arg any, ok bool) {
	term = strings.TrimSpace(term)
	if !t.fts || utf8.RuneCountInString(term) < minTrigram {
		return "", nil, false
	}
	return `rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)`, ftsQuote(term), true
}

// ftsQuote wraps a term as an FTS5 string literal so that punctuation and query
// operators inside it (quotes, AND/OR/NEAR, *, ^) are matched literally instead
// of being parsed as query syntax.
func ftsQuote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// PageQuery bundles the optional filters and sort order for Page. Every filter
// is combined with AND; an empty string skips that filter, and RespMin/RespMax
// of -1 skip the response-size bounds. An empty Sort/Order defaults to
// newest-first by timestamp.
type PageQuery struct {
	Host    string // host substring
	Method  string // exact method (case-insensitive)
	Query   string // broad search box: metadata columns OR captured text
	Body    string // content box: captured request/response text only (full-text)
	Path    string // url_template substring — the vulnerability's path
	Status  string // exact code ("404") or class bucket ("4xx")
	RespMin int64  // minimum resp_len, or -1 when unset
	RespMax int64  // maximum resp_len, or -1 when unset
	Sort    string // ts | status | resp_len (default ts)
	Order   string // asc | desc (default desc)
}

// sortColumns whitelists the columns Page may order by, so the caller-supplied
// Sort can never reach the SQL as anything but one of these fixed names.
var sortColumns = map[string]string{"ts": "ts", "status": "status", "resp_len": "resp_len"}

// statusFilter turns a status token into a SQL condition: an exact code ("404")
// matches that status, an "Nxx" class ("4xx") matches the whole hundreds band.
// ok is false for an empty or unrecognized token.
func statusFilter(s string) (cond string, args []any, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "", nil, false
	}
	if len(s) == 3 && s[0] >= '1' && s[0] <= '5' && s[1] == 'x' && s[2] == 'x' {
		base := int(s[0]-'0') * 100
		return "status>=? AND status<?", []any{base, base + 100}, true
	}
	if n, err := strconv.Atoi(s); err == nil {
		return "status=?", []any{n}, true
	}
	return "", nil, false
}

// Page returns one page of exchange metadata for the traffic list, filtered by
// the criteria in f (all optional, combined with AND) and ordered by the
// requested column. Query is the broad search box (metadata columns OR, when the
// term is long enough for the trigram index, captured request/response text);
// Body narrows to exchanges whose captured text matches, via that same index.
// Also returns the total number of rows matching the filter (for the UI's
// pagination). Bodies are never included in the rows.
func (t *Traffic) Page(f PageQuery, page, size int) (rows []ExchangeMeta, total int, err error) {
	if size <= 0 || size > 500 {
		size = 100
	}
	if page < 0 {
		page = 0
	}
	where := ""
	var args []any
	add := func(cond string, vs ...any) {
		if where == "" {
			where = " WHERE "
		} else {
			where += " AND "
		}
		where += cond
		args = append(args, vs...)
	}
	if h := strings.TrimSpace(f.Host); h != "" {
		add("host LIKE ?", "%"+h+"%")
	}
	if m := strings.TrimSpace(f.Method); m != "" {
		add("method=?", strings.ToUpper(m))
	}
	if p := strings.TrimSpace(f.Path); p != "" {
		add("url_template LIKE ?", "%"+p+"%")
	}
	if cond, sargs, ok := statusFilter(f.Status); ok {
		add(cond, sargs...)
	}
	if f.RespMin >= 0 {
		add("resp_len>=?", f.RespMin)
	}
	if f.RespMax >= 0 {
		add("resp_len<=?", f.RespMax)
	}
	if s := strings.TrimSpace(f.Query); s != "" {
		like := "%" + s + "%"
		const meta = "host LIKE ? OR url LIKE ? OR url_template LIKE ? OR method LIKE ? OR content_type LIKE ? OR CAST(status AS TEXT) LIKE ?"
		// Metadata match OR full-text match: one search box, widest recall. Terms
		// too short for trigram silently fall back to metadata only.
		if cond, arg, ok := t.ftsFilter(s); ok {
			add("(("+meta+") OR "+cond+")", like, like, like, like, like, like, arg)
		} else {
			add("("+meta+")", like, like, like, like, like, like)
		}
	}
	// Body is the dedicated content box: it only searches captured request/response
	// text, so it goes straight to the full-text index with no metadata fallback. A
	// term too short for the trigram tokenizer cannot be served and is skipped
	// rather than guessed at — the UI hints at the three-character minimum.
	if b := strings.TrimSpace(f.Body); b != "" {
		if cond, arg, ok := t.ftsFilter(b); ok {
			add(cond, arg)
		}
	}
	if err = t.db.QueryRow(`SELECT COUNT(*) FROM exchanges`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	col := sortColumns[strings.ToLower(strings.TrimSpace(f.Sort))]
	if col == "" {
		col = "ts"
	}
	dir := "DESC"
	if strings.EqualFold(strings.TrimSpace(f.Order), "asc") {
		dir = "ASC"
	}
	// id embeds capture timestamp + sequence, so a trailing id DESC makes the order
	// total and pagination stable even when the sort column has many ties.
	sel := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path FROM exchanges` +
		where + ` ORDER BY ` + col + ` ` + dir + `, id DESC LIMIT ? OFFSET ?`
	qargs := append(append([]any{}, args...), size, page*size)
	rs, err := t.db.Query(sel, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rs.Close()
	for rs.Next() {
		var m ExchangeMeta
		if err := rs.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path); err != nil {
			return nil, 0, err
		}
		rows = append(rows, m)
	}
	return rows, total, rs.Err()
}

// Get returns the full request/response text of one exchange. Bodies come from
// the database; rows recorded before bodies moved into SQLite carry a non-empty
// path and are read from the legacy on-disk tree instead, so history stays
// readable without being migrated.
func (t *Traffic) Get(id string) (req, resp string, err error) {
	var reqHead, respHead string
	var reqBody, respBody []byte
	var reqBlob, respBlob sql.NullString
	var reqLen, respLen int
	err = t.db.QueryRow(`SELECT b.req_head,b.req_body,b.req_blob,b.resp_head,b.resp_body,b.resp_blob,e.req_len,e.resp_len
FROM exchange_bodies b JOIN exchanges e ON e.id=b.id WHERE b.id=?`, id).
		Scan(&reqHead, &reqBody, &reqBlob, &respHead, &respBody, &respBlob, &reqLen, &respLen)
	if err == nil {
		return assembleRaw(reqHead, reqBody, reqBlob, reqLen), assembleRaw(respHead, respBody, respBlob, respLen), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", "", err
	}

	var rel string
	if err = t.db.QueryRow(`SELECT path FROM exchanges WHERE id=?`, id).Scan(&rel); err != nil {
		return "", "", err
	}
	if strings.TrimSpace(rel) == "" {
		return "", "", fmt.Errorf("exchange %s 无正文记录", id)
	}
	rb, _ := os.ReadFile(filepath.Join(t.dir, rel, "request.http"))
	pb, _ := os.ReadFile(filepath.Join(t.dir, rel, "response.http"))
	return string(rb), string(pb), nil
}

// assembleRaw rebuilds one side's raw HTTP text: head, blank line, body. A body
// that spilled to the blob store shows its inline preview followed by the blob
// pointer, so the reader can see what it is and fetch the rest by hash.
func assembleRaw(head string, body []byte, blob sql.NullString, total int) string {
	var b strings.Builder
	b.WriteString(head)
	b.WriteByte('\n')
	b.Write(body)
	if blob.Valid && blob.String != "" {
		fmt.Fprintf(&b, "\n…[truncated] @blob sha256:%s (len=%d)", blob.String, total)
	}
	return b.String()
}

// HostCount is one distinct recorded host plus its exchange count.
type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

// Hosts returns distinct recorded hosts with exchange counts, most recent
// activity first — powers the page's target picker.
func (t *Traffic) Hosts() ([]HostCount, error) {
	rows, err := t.db.Query(`SELECT host, COUNT(*) AS n, MAX(ts) AS last FROM exchanges GROUP BY host ORDER BY last DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostCount
	for rows.Next() {
		var h HostCount
		var last int64
		if err := rows.Scan(&h.Host, &h.Count, &last); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Count returns total recorded exchanges.
func (t *Traffic) Count() (int, error) {
	var n int
	err := t.db.QueryRow(`SELECT COUNT(*) FROM exchanges`).Scan(&n)
	return n, err
}

// DeleteHost removes every recorded exchange whose host contains the given
// substring — mirroring the UI's host filter, so what you filtered is what gets
// deleted. The filter is resolved to the exact hosts it hit before anything is
// touched, because the index is the only record of which host directories the
// filter matched, and an exact host set is what the staged purge takes.
// Content-addressed blobs are shared across hosts and so are garbage-collected
// afterwards rather than deleted by host. Returns rows deleted.
func (t *Traffic) DeleteHost(host string) (int64, error) {
	hosts, err := t.matchingHosts(`host LIKE ?`, "%"+host+"%")
	if err != nil {
		return 0, err
	}
	return t.purgeHosts(hosts, 0, 0)
}

// DeleteAll removes every recorded exchange — the page's clear-everything
// action. It differs from the host-scoped deletions in two ways. It sweeps host
// directories without consulting the index, because "clear everything" should
// leave nothing behind and a directory whose rows are already gone would
// otherwise survive. And it ends with a full compaction: VACUUM costs what it
// keeps, so an emptied index is the one moment it is free, and it is also the
// only way to switch on auto_vacuum for a database created without it.
//
// Evidence already bound to a finding is untouched. Those bodies were copied
// into the evidence store when they were bound, precisely so that disposable
// traffic could be cleared without taking proof with it.
//
// Returns the number of exchanges deleted and how many bytes of index the
// compaction handed back.
func (t *Traffic) DeleteAll() (deleted int64, reclaimed int64, err error) {
	before := t.indexBytes()
	stage, err := t.stageDeletePlan(true, nil, 0, 0)
	if err != nil {
		return 0, 0, err
	}
	if err := stage.Commit(); err != nil {
		return stage.Deleted(), 0, err
	}
	deleted = stage.Deleted()
	// The compaction holds the write lock for its whole run, which is part of why
	// it is a clear-everything-only step: there is nothing left to record over.
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if err := t.compactIndex(); err != nil {
		// The deletion is already durable; compaction is disk space, not
		// correctness, so it must not turn a completed purge into a failed one.
		log.Printf("[traffic] 压实索引失败：%v", err)
		return deleted, 0, nil
	}
	return deleted, before - t.indexBytes(), nil
}

// allHostTrees lists every host directory left by the pre-SQLite layout. Unlike
// hostTrees it does not go through the index, so it also finds directories whose
// rows are already gone. Underscore-prefixed entries are the store's own
// (_index, _blobs, _ca, _delete_staging) and are never hosts.
func (t *Traffic) allHostTrees() ([]string, error) {
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") {
			dirs = append(dirs, filepath.Join(t.dir, e.Name()))
		}
	}
	return dirs, nil
}

// compactIndex rewrites the index into a fresh file, which is what actually
// returns its pages to the filesystem. VACUUM's runtime and temporary space
// scale with the content it keeps, so this is only reached right after DeleteAll
// has emptied the index — never as a routine step. It doubles as the conversion
// path for a database created before auto_vacuum=incremental: that pragma only
// takes effect through the VACUUM that follows it, and both must run on the same
// connection. Callers must hold wmu.
func (t *Traffic) compactIndex() error {
	ctx := context.Background()
	conn, err := t.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if t.fts {
		// A full merge, not the bounded one reclaim uses: with the index emptied
		// there is nothing left to merge, so this only discards the tombstones.
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts) VALUES('optimize')`); err != nil {
			return fmt.Errorf("合并全文索引: %w", err)
		}
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA auto_vacuum=incremental`); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("压实索引: %w", err)
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return err
	}
	// A legacy database has just been converted, so later deletions can reclaim
	// space on their own instead of waiting for another purge.
	t.incrementalVacuum = mode == autoVacuumIncremental
	if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("截断 WAL: %w", err)
	}
	return nil
}

// deleteRowsTx removes every trace of one bounded set of exchange rows: the
// full-text index rows, bodies, blob references, and finally the index rows.
// Order matters — each sub-select reads exchanges, so that table is emptied last.
func (t *Traffic) deleteRowsTx(tx *sql.Tx, rowids []int64) (int64, error) {
	if len(rowids) == 0 {
		return 0, nil
	}
	// A placeholder cannot stand for a list of values, and the batch is a small
	// constant, so the statement text is built per batch.
	in := strings.TrimSuffix(strings.Repeat("?,", len(rowids)), ",")
	args := make([]any, len(rowids))
	for i, rowid := range rowids {
		args[i] = rowid
	}
	if t.fts {
		// ex_fts is contentless and addressed by rowid, hence the explicit row set.
		if _, err := tx.Exec(`DELETE FROM ex_fts WHERE rowid IN (`+in+`)`, args...); err != nil {
			return 0, fmt.Errorf("删除全文索引: %w", err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM exchange_bodies WHERE id IN (SELECT id FROM exchanges WHERE rowid IN (`+in+`))`, args...); err != nil {
		return 0, fmt.Errorf("删除正文: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM blob_refs WHERE exchange_id IN (SELECT id FROM exchanges WHERE rowid IN (`+in+`))`, args...); err != nil {
		return 0, fmt.Errorf("删除 blob 引用: %w", err)
	}
	res, err := tx.Exec(`DELETE FROM exchanges WHERE rowid IN (`+in+`)`, args...)
	if err != nil {
		return 0, fmt.Errorf("删除索引行: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// deleteBatchTx removes at most limit rows matching where. The row set is chosen
// inside the transaction that deletes it, so all four statements above address
// the same rows.
func (t *Traffic) deleteBatchTx(tx *sql.Tx, limit int, where string, args ...any) (int64, error) {
	queryArgs := make([]any, 0, len(args)+1)
	queryArgs = append(queryArgs, args...)
	queryArgs = append(queryArgs, limit)
	rowids, err := scanRowIDs(tx, `SELECT rowid FROM exchanges WHERE `+where+` LIMIT ?`, queryArgs...)
	if err != nil {
		return 0, fmt.Errorf("选择待删流量: %w", err)
	}
	return t.deleteRowsTx(tx, rowids)
}

// runDeleteBatch runs one bounded deletion as its own transaction, holding the
// traffic write lock for that batch only, and reports what that hold cost. Every
// purge goes through here, which is what keeps record() — and so every in-flight
// proxied request, which go-mitmproxy only answers after it has been recorded —
// from waiting behind a deletion that runs for hours.
func (t *Traffic) runDeleteBatch(fn func(*sql.Tx) (int64, error)) (int64, time.Duration, error) {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	// Timed from the moment the lock is ours: the wait for it is other writers'
	// work, and this measurement is what sizes the next batch.
	began := time.Now()
	tx, err := t.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed
	n, err := fn(tx)
	if err != nil {
		return 0, time.Since(began), err
	}
	if err := tx.Commit(); err != nil {
		return 0, time.Since(began), fmt.Errorf("提交流量索引删除: %w", err)
	}
	return n, time.Since(began), nil
}

// nextDeleteBatch picks the size of the next purge batch from what the last one
// cost: see the constants for why the cost of a row is not a property of the row
// count.
func nextDeleteBatch(current int, held time.Duration) int {
	switch {
	case held > deleteBatchHoldBudget:
		return max(current/2, deleteBatchMinRows)
	case held < deleteBatchHoldBudget/4:
		return min(current*2, deleteBatchMaxRows)
	default:
		return current
	}
}

// purgeCheckpointBytes is the write-ahead log size at which a purge checkpoints
// it while no lock is held. Keeping the log near one autocheckpoint threshold
// (SQLite's default is 1000 pages, so ~4MB) is what keeps the automatic
// checkpoint that runs inside a commit — and therefore inside the write lock —
// proportional to one batch rather than to everything the purge has evicted so
// far.
const purgeCheckpointBytes = 4 << 20

// checkpointIfWalLarge hands the write-ahead log back to the database between
// steps, outside the write lock. Measured on the 2026-10-19 benchmark, deleting a
// full-text-heavy host wrote over 15MB of evicted pages and tombstones into the
// log, and the automatic checkpoint SQLite then ran inside a committing writer
// held the lock for up to 13s — a stall record() pays for, since it runs before
// go-mitmproxy answers a client. A PASSIVE checkpoint copies whatever frames it
// can without blocking anyone, so writers — record() included — keep running
// while it does.
func (t *Traffic) checkpointIfWalLarge() {
	st, err := os.Stat(filepath.Join(t.dir, "_index", "index.sqlite-wal"))
	if err != nil || st.Size() < purgeCheckpointBytes {
		return
	}
	if _, err := t.db.Exec(`PRAGMA wal_checkpoint(PASSIVE)`); err != nil {
		log.Printf("[traffic] 回收 WAL 失败：%v", err)
	}
}

// deletePlannedRows purges the exact row set a stage captured, in bounded
// batches.
func (t *Traffic) deletePlannedRows(rowids []int64) (int64, error) {
	var deleted int64
	batch := deleteBatchInitialRows
	for start := 0; start < len(rowids); {
		end := min(start+batch, len(rowids))
		n, held, err := t.runDeleteBatch(func(tx *sql.Tx) (int64, error) {
			return t.deleteRowsTx(tx, rowids[start:end])
		})
		deleted += n
		if err != nil {
			return deleted, err
		}
		batch = nextDeleteBatch(batch, held)
		start = end
		t.checkpointIfWalLarge()
	}
	return deleted, nil
}

// deleteMatchingRows purges everything matching where, one bounded batch at a
// time, until nothing is left. It is the resumed form of a purge: startup
// recovery re-derives the row set from the predicate instead of a captured plan.
func (t *Traffic) deleteMatchingRows(where string, args ...any) (int64, error) {
	var deleted int64
	batch := deleteBatchInitialRows
	for {
		n, held, err := t.runDeleteBatch(func(tx *sql.Tx) (int64, error) {
			return t.deleteBatchTx(tx, batch, where, args...)
		})
		deleted += n
		if err != nil {
			return deleted, err
		}
		if n == 0 {
			return deleted, nil
		}
		batch = nextDeleteBatch(batch, held)
		t.checkpointIfWalLarge()
	}
}

// rowQuerier is the subset of *sql.DB and *sql.Tx that reads exchange row ids.
type rowQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// scanRowIDs reads one column of exchange row ids. Bounded by LIMIT, the order
// does not matter: a batched purge loops until nothing matches, and a planned
// purge captures the ids once and deletes exactly them.
func scanRowIDs(q rowQuerier, query string, args ...any) ([]int64, error) {
	rows, err := q.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// matchingHosts returns the distinct recorded hosts matching the condition.
// Exchanges recorded since bodies moved into SQLite have no directory at all, so
// most of these hosts own no tree; the lookup is deliberately not restricted to
// rows with a path, because a host whose index rows are already gone can still
// have an orphaned directory, and deleting the host should take that with it.
func (t *Traffic) matchingHosts(where string, args ...any) ([]string, error) {
	rows, err := t.db.Query(`SELECT DISTINCT host FROM exchanges WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hosts []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}
	return hosts, rows.Err()
}

type stagedTrafficPath struct {
	source string
	staged string
}

// hostDeleteStageJournal is the on-disk record of one staged purge: what it
// covers, whether it is still reversible, and where its trees went. It is the
// only thing that survives a process exit mid-purge, so it carries everything
// startup recovery needs to decide between restoring the trees and finishing the
// deletion.
type hostDeleteStageJournal struct {
	Version int    `json:"version"`
	Phase   string `json:"phase"`
	// All marks a clear-everything purge, whose row set is "every remaining
	// exchange" rather than a host list.
	All       bool                  `json:"all,omitempty"`
	ArchiveID int64                 `json:"archive_id,omitempty"`
	TaskID    int64                 `json:"task_id,omitempty"`
	Hosts     []string              `json:"hosts,omitempty"`
	Moves     []hostDeleteStageMove `json:"moves"`
}

type hostDeleteStageMove struct {
	Source string `json:"source"`
	Staged string `json:"staged"`
}

const hostDeleteStageJournalName = "journal.json"

// stageTreesForArchive moves host directories aside onto the same filesystem and
// records the purge in a journal. The rename is atomic and instant, which buys two
// things the unlink cannot: the deletion stays reversible until it is committed,
// and the tree stops being visible to blob reference collection right away
// (legacyBlobRefs skips underscore-prefixed directories, so anything under
// _delete_staging is already out of the live set). An empty stageDir is returned
// when there was nothing to both stage and remember.
func (t *Traffic) stageTreesForArchive(journal hostDeleteStageJournal, dirs []string) (stageDir string, moves []stagedTrafficPath, err error) {
	seen := make(map[string]struct{}, len(dirs))
	planned := make([]stagedTrafficPath, 0, len(dirs))
	for _, source := range dirs {
		if _, dup := seen[source]; dup {
			continue
		}
		seen[source] = struct{}{}
		if _, err := os.Lstat(source); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return stageDir, moves, fmt.Errorf("检查历史流量目录 %s: %w", source, err)
		}
		planned = append(planned, stagedTrafficPath{source: source})
	}
	// 归档路径即使一个历史 host 目录都没有(新装机的流量只落在 SQLite + _blobs)
	// 也必须留下 journal：崩溃点若落在 PostgreSQL 提交与本次提交之间，重启后只有这份
	// journal 能让恢复流程补做 host 行的删除。少了它，已转冷任务的独占流量会永久留在
	// 热库里。
	if len(planned) == 0 && len(journal.Hosts) == 0 && !journal.All {
		return "", nil, nil
	}
	parent := filepath.Join(t.dir, "_delete_staging")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", nil, fmt.Errorf("创建流量暂存目录: %w", err)
	}
	if stageDir, err = os.MkdirTemp(parent, "hosts-"); err != nil {
		return "", nil, fmt.Errorf("创建流量暂存目录: %w", err)
	}
	for i := range planned {
		planned[i].staged = filepath.Join(stageDir, fmt.Sprintf("%d-%s", i, filepath.Base(planned[i].source)))
		journal.Moves = append(journal.Moves, hostDeleteStageMove{Source: planned[i].source, Staged: planned[i].staged})
	}
	if err := writeHostDeleteStageJournal(filepath.Join(stageDir, hostDeleteStageJournalName), journal); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", nil, err
	}
	for _, move := range planned {
		source, staged := move.source, move.staged
		if err := os.Rename(source, staged); err != nil {
			return stageDir, moves, fmt.Errorf("移出历史流量目录 %s: %w", source, err)
		}
		moves = append(moves, stagedTrafficPath{source: source, staged: staged})
	}
	return stageDir, moves, nil
}

func writeHostDeleteStageJournal(path string, journal hostDeleteStageJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

// rewriteHostDeleteStageJournal replaces a stage journal in place. The initial
// journal is written exclusively (O_EXCL) because it must never clobber another
// stage; this one only moves an existing stage past its commit marker, so it goes
// to a temporary file, is synced, and is renamed over the original: a crash
// leaves either the old journal or the new one, never a torn one.
func rewriteHostDeleteStageJournal(path string, journal hostDeleteStageJournal) error {
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// restoreTrees puts staged directories back where they came from, newest move
// first, and drops the staging directory once everything is home.
func restoreTrees(stageDir string, moves []stagedTrafficPath) error {
	var errs []error
	for i := len(moves) - 1; i >= 0; i-- {
		move := moves[i]
		if _, err := os.Lstat(move.source); err == nil {
			errs = append(errs, fmt.Errorf("restore destination already exists: %s", move.source))
			continue
		} else if !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("inspect restore destination %s: %w", move.source, err))
			continue
		}
		if err := os.Rename(move.staged, move.source); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", move.source, err))
		}
	}
	if len(errs) == 0 && stageDir != "" {
		if err := os.RemoveAll(stageDir); err != nil {
			errs = append(errs, fmt.Errorf("remove traffic stage: %w", err))
		}
	}
	return errors.Join(errs...)
}

// reapStage unlinks a committed staging directory in the background. This is the
// step that used to stall the recorder: a legacy tree mirrors the URL path per
// request and can hold hundreds of thousands of small files, and the whole unlink
// ran while the write lock was held. The rows are already gone by now, so losing
// this to a shutdown leaves garbage under _delete_staging, never inconsistent
// state.
func (t *Traffic) reapStage(stageDir string) {
	if stageDir == "" {
		return
	}
	t.reaping.Go(func() {
		if err := os.RemoveAll(stageDir); err != nil {
			log.Printf("[traffic] 清理历史流量目录 %s 失败：%v", stageDir, err)
		}
	})
}

// DeleteHostsExact removes recorded exchanges for a set of EXACT hosts (the
// batch path for the page's multi-select delete): index rows + each host's file
// tree, then one blob-GC pass. Exact match — unlike DeleteHost's substring —
// so picking "api.example.com" never sweeps "api.example.com.cn". Returns rows
// deleted. Duplicate hosts are harmless (idempotent deletes, single tree pass).
func (t *Traffic) DeleteHostsExact(hosts []string) (int64, error) {
	return t.purgeHosts(hosts, 0, 0)
}

// purgeHosts stages and immediately commits an exact-host purge.
func (t *Traffic) purgeHosts(hosts []string, archiveID, taskID int64) (int64, error) {
	stage, err := t.stageDeletePlan(false, hosts, archiveID, taskID)
	if err != nil {
		return 0, err
	}
	if err := stage.Commit(); err != nil {
		return stage.Deleted(), err
	}
	return stage.Deleted(), nil
}

// HostDeleteStage is a staged, reversible, restartable purge. Staging captures
// the exact rows it will remove and moves the legacy host trees aside, and it
// deletes nothing: the caller can still coordinate the purge with its own
// database transaction — PostgreSQL commits first, and only then is this commit
// called — and a Rollback hands back a store that is exactly what it found.
//
// Commit then removes the captured rows in bounded batches, each its own
// transaction with the write lock held only for that batch, so a purge of any
// size leaves record() free to interleave. Before the first row goes it records
// the decision in the stage journal, which is what lets a process exit mid-purge
// resume the deletion on startup rather than restore trees over a half-deleted
// index. Nothing is held across the caller's own transaction: no SQLite
// transaction, no write lock.
type HostDeleteStage struct {
	traffic  *Traffic
	journal  hostDeleteStageJournal
	stageDir string
	moves    []stagedTrafficPath
	// rowids is the plan captured at stage time. Purging exactly these keeps the
	// operation a deletion of what the caller saw: rows recorded while it runs get
	// row ids past every id here and survive it.
	rowids  []int64
	deleted int64
	done    bool
}

// Deleted reports the number of exchange rows selected by this stage — or, after
// a Commit that could not finish, the number it did manage to remove.
func (s *HostDeleteStage) Deleted() int64 {
	if s == nil {
		return 0
	}
	return s.deleted
}

// StageDeleteHostsExact prepares a reversible exact-host deletion. Callers must
// finish every successful stage with Commit or Rollback.
func (t *Traffic) StageDeleteHostsExact(hosts []string) (*HostDeleteStage, error) {
	return t.stageDeletePlan(false, hosts, 0, 0)
}

// StageDeleteHostsExactForArchive ties the reversible traffic deletion to a
// persistent task archive. Startup recovery uses archiveCommitted to decide
// whether an interrupted stage must be completed or rolled back.
func (t *Traffic) StageDeleteHostsExactForArchive(hosts []string, archiveID, taskID int64) (*HostDeleteStage, error) {
	if archiveID <= 0 || taskID <= 0 {
		return nil, errors.New("archive and task ids must be positive")
	}
	return t.stageDeletePlan(false, hosts, archiveID, taskID)
}

// stageDeletePlan records one purge: the rows to remove, the legacy trees to move
// aside, and the journal entry startup recovery reads. all selects "every
// remaining exchange" (the clear-everything action) instead of an exact host set.
// Nothing is deleted here, so the caller holds no long lock across its own
// transaction — only the time this plan takes to capture.
func (t *Traffic) stageDeletePlan(all bool, hosts []string, archiveID, taskID int64) (*HostDeleteStage, error) {
	stage := &HostDeleteStage{
		traffic: t,
		journal: hostDeleteStageJournal{Version: 2, Phase: hostDeletePhaseStaged, All: all, ArchiveID: archiveID, TaskID: taskID},
	}
	unique := uniqueArchiveHosts(hosts)
	if !all {
		stage.journal.Hosts = unique
	}

	t.wmu.Lock()
	defer t.wmu.Unlock()

	if all {
		rowids, err := scanRowIDs(t.db, `SELECT rowid FROM exchanges`)
		if err != nil {
			return nil, err
		}
		stage.rowids = rowids
	} else {
		for _, host := range unique {
			rowids, err := scanRowIDs(t.db, `SELECT rowid FROM exchanges WHERE host=?`, host)
			if err != nil {
				return nil, err
			}
			stage.rowids = append(stage.rowids, rowids...)
		}
	}
	stage.deleted = int64(len(stage.rowids))

	trees := make([]string, 0, len(unique))
	if all {
		// Clear-everything sweeps the tree, not the index: a directory whose rows are
		// already gone has no host to derive it from and must still go.
		var err error
		if trees, err = t.allHostTrees(); err != nil {
			return nil, err
		}
	} else {
		// Exact hosts are known up front, so their directories are derived directly
		// rather than looked up: a host whose index rows are already gone can still
		// own an orphaned directory that this deletion should take with it.
		for _, host := range unique {
			trees = append(trees, filepath.Join(t.dir, sanitize(host)))
		}
	}
	stageDir, moves, err := t.stageTreesForArchive(stage.journal, trees)
	if err != nil {
		return nil, errors.Join(err, restoreTrees(stageDir, moves))
	}
	stage.stageDir, stage.moves = stageDir, moves
	return stage, nil
}

// RecoverHostDeleteStages resolves staged host purges left by a process exit. A
// purge whose commit marker never landed is rolled back: its trees go back and
// its rows were never touched. One whose marker did land is finished here, in
// bounded batches, instead of being left half-deleted — and so is a journal
// written before that marker existed, recognised by the callback below, which
// identifies the task archives whose PostgreSQL compaction already committed.
//
// Each staging directory is removed only after its purge is complete, so the
// journal survives exactly as long as the work it describes.
func (t *Traffic) RecoverHostDeleteStages(archiveCommitted func(int64, int64) (bool, error)) error {
	if t == nil {
		return nil
	}
	parent := filepath.Join(t.dir, "_delete_staging")
	entries, err := os.ReadDir(parent)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	needsGC := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		stageDir := filepath.Join(parent, entry.Name())
		raw, err := os.ReadFile(filepath.Join(stageDir, hostDeleteStageJournalName))
		if os.IsNotExist(err) {
			// Older versions did not persist enough information for lossless
			// recovery. Keep the directory for manual inspection.
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var journal hostDeleteStageJournal
		if err := json.Unmarshal(raw, &journal); err != nil {
			errs = append(errs, fmt.Errorf("读取流量暂存日志 %s: %w", stageDir, err))
			continue
		}
		if journal.Version != 1 && journal.Version != 2 {
			errs = append(errs, fmt.Errorf("流量暂存日志 %s 的版本 %d 不受支持", stageDir, journal.Version))
			continue
		}
		moves := make([]stagedTrafficPath, 0, len(journal.Moves))
		for _, move := range journal.Moves {
			if !pathWithin(t.dir, move.Source) || !pathWithin(stageDir, move.Staged) {
				errs = append(errs, fmt.Errorf("流量暂存日志包含越界路径: %s", stageDir))
				moves = nil
				break
			}
			if _, err := os.Lstat(move.Staged); err == nil {
				moves = append(moves, stagedTrafficPath{source: move.Source, staged: move.Staged})
			} else if !os.IsNotExist(err) {
				errs = append(errs, err)
				moves = nil
				break
			}
		}
		if moves == nil {
			continue
		}
		committed := journal.Phase == hostDeletePhaseDeleting
		if !committed {
			switch {
			case journal.ArchiveID > 0 && archiveCommitted == nil:
				errs = append(errs, fmt.Errorf("流量归档 %d 无状态解析器", journal.ArchiveID))
				continue
			case journal.ArchiveID > 0:
				committed, err = archiveCommitted(journal.ArchiveID, journal.TaskID)
			case len(journal.Hosts) > 0:
				committed, err = t.hostsHaveNoExchanges(journal.Hosts)
			}
			if err != nil {
				errs = append(errs, err)
				continue
			}
		}
		if !committed {
			t.wmu.Lock()
			err := restoreTrees(stageDir, moves)
			t.wmu.Unlock()
			if err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := t.finishPendingDelete(journal); err != nil {
			errs = append(errs, err)
			continue
		}
		t.wmu.Lock()
		err = os.RemoveAll(stageDir)
		t.wmu.Unlock()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		needsGC = true
	}
	if needsGC {
		t.reclaim()
		t.wmu.Lock()
		err := t.gcBlobs()
		t.wmu.Unlock()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *Traffic) hostsHaveNoExchanges(hosts []string) (bool, error) {
	for _, host := range hosts {
		var count int
		if err := t.db.QueryRow(`SELECT count(*) FROM exchanges WHERE host=?`, host).Scan(&count); err != nil {
			return false, err
		}
		if count > 0 {
			return false, nil
		}
	}
	return true, nil
}

// finishPendingDelete completes a purge whose commit is durable: everything it
// still covers goes, a bounded batch per transaction, with the write lock
// released in between. The row set is re-derived from the predicate rather than
// from a captured plan, which is why this form is reserved for recovery — it runs
// before the proxy starts, so nothing new can arrive underneath it.
func (t *Traffic) finishPendingDelete(journal hostDeleteStageJournal) error {
	if journal.All {
		_, err := t.deleteMatchingRows(`1=1`)
		return err
	}
	for _, host := range journal.Hosts {
		if _, err := t.deleteMatchingRows(`host=?`, host); err != nil {
			return err
		}
	}
	return nil
}

func pathWithin(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, candidateAbs)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

// Rollback discards the staged purge. Nothing was deleted — the plan was only
// captured, and the trees were moved aside rather than unlinked — so this puts
// the trees back and leaves the caller with exactly the store it had.
func (s *HostDeleteStage) Rollback() error {
	if s == nil || s.done {
		return nil
	}
	s.done = true
	return restoreTrees(s.stageDir, s.moves)
}

// Commit makes the staged purge permanent. It is called only after the caller's
// own database transaction has committed, and it neither opens a SQLite
// transaction nor holds the write lock across its work: the rows go in bounded
// batches, one transaction each, so record() keeps interleaving with a purge of
// any size.
func (s *HostDeleteStage) Commit() error {
	if s == nil || s.done {
		return nil
	}
	s.done = true
	t := s.traffic
	if s.stageDir != "" {
		// The decision has to be durable before the first row goes: a process exit
		// after this point must finish the deletion, and this marker is the only
		// thing that tells startup recovery apart from "the caller rolled back".
		journal := s.journal
		journal.Phase = hostDeletePhaseDeleting
		if err := rewriteHostDeleteStageJournal(filepath.Join(s.stageDir, hostDeleteStageJournalName), journal); err != nil {
			// Nothing was deleted, so the purge simply did not happen; put the trees
			// back and report it rather than deleting rows recovery cannot account for.
			return errors.Join(fmt.Errorf("标记流量删除已提交: %w", err), restoreTrees(s.stageDir, s.moves))
		}
		s.journal = journal
	}
	// Write-time segment merging is proportional to the index the purge is
	// shrinking, so it is suspended for the delete and restored after — even on
	// failure, since the setting outlives the process.
	resumeAutoMerge := t.suspendFTSAutoMerge()
	defer resumeAutoMerge()
	deleted, err := t.deletePlannedRows(s.rowids)
	s.deleted = deleted
	if err != nil {
		// The batches already committed cannot be undone, so the store is left
		// showing what it is: some rows gone, the trees put back, and the failure
		// reported. Retrying the purge re-plans whatever is left.
		return errors.Join(err, restoreTrees(s.stageDir, s.moves))
	}
	s.rowids = nil
	t.reapStage(s.stageDir)
	if deleted > 0 || s.stageDir != "" {
		if deleted > 0 {
			t.reclaim()
		}
		t.wmu.Lock()
		err := t.gcBlobs()
		t.wmu.Unlock()
		if err != nil {
			return fmt.Errorf("回收流量 blob: %w", err)
		}
	}
	return nil
}

// indexBytes is the index's real footprint on disk: the database plus its
// write-ahead log and shared-memory file, since those are what an operator sees
// the data directory holding.
func (t *Traffic) indexBytes() int64 {
	base := filepath.Join(t.dir, "_index", "index.sqlite")
	var total int64
	for _, p := range []string{base, base + "-wal", base + "-shm"} {
		if st, err := os.Stat(p); err == nil {
			total += st.Size()
		}
	}
	return total
}

// reclaim hands space freed by a deletion back to the filesystem. Deleting rows
// only makes them invisible: SQLite chains their pages onto a freelist, and
// deleting from the contentless_delete full-text index writes tombstones rather
// than removing the postings they hide. Neither shrinks a single byte on disk,
// and since bodies below maxInlineBody live in that same file, an install that
// captures heavily ends up holding far more than the traffic it still has.
//
// The work is done in the background, in bounded steps that drop the write lock
// between them, because it is proportional to what was deleted — freeing several
// gigabytes under one lock would stall record(), which go-mitmproxy calls before
// it replies to the client, and so would stall the requests being recorded.
// Safe to call with wmu held: the background pass simply waits for it.
//
// Best-effort throughout. Failing to reclaim costs disk space, never
// correctness, so errors are logged and the next deletion resumes the work.
func (t *Traffic) reclaim() {
	if !t.reclaiming.CompareAndSwap(false, true) {
		return // one pass at a time; a second would only contend for the lock
	}
	t.reaping.Go(func() {
		defer t.reclaiming.Store(false)
		// One pinned connection for the whole pass: a long reclamation issues
		// hundreds of statements, and letting the pool hand each one a different
		// connection would both churn connections and split the freelist readings
		// that decide when to stop away from the vacuum they measure.
		ctx := context.Background()
		conn, err := t.db.Conn(ctx)
		if err != nil {
			log.Printf("[traffic] 回收索引空间失败（获取连接）：%v", err)
			return
		}
		defer conn.Close()
		deadline := time.Now().Add(reclaimBudget)
		merges := reclaimMergeSteps
		for step := 0; ; step++ {
			t.wmu.Lock()
			progressed, err := t.reclaimChunk(ctx, conn, &merges)
			t.wmu.Unlock()
			if err != nil {
				log.Printf("[traffic] 回收索引空间失败：%v", err)
				return
			}
			if !progressed {
				break
			}
			if t.stopping() {
				return // shutdown must not wait out the remaining budget
			}
			if step+1 >= reclaimMaxSteps {
				log.Printf("[traffic] 索引空间回收未做完（已用满 %d 步上限），下次删除时继续", reclaimMaxSteps)
				return
			}
			if time.Now().After(deadline) {
				log.Printf("[traffic] 索引空间回收未做完（已用满 %s 预算），下次删除时继续", reclaimBudget)
				return
			}
		}
		// Truncating the log is what makes the reclamation visible on disk: in WAL
		// mode the freed pages are recorded there first, and a PASSIVE checkpoint
		// would leave the log itself sitting at its high-water mark.
		t.wmu.Lock()
		defer t.wmu.Unlock()
		if _, err := conn.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			log.Printf("[traffic] 截断 WAL 失败：%v", err)
		}
	})
}

// reclaimChunk does one bounded step and reports whether it made progress, which
// is what the caller loops on. merges carries the remaining full-text merge
// budget and is spent down here. Callers must hold wmu.
func (t *Traffic) reclaimChunk(ctx context.Context, conn *sql.Conn, merges *int) (bool, error) {
	progressed := false
	if t.fts && *merges > 0 {
		// A negative rank is fts5's page budget for one incremental merge.
		if _, err := conn.ExecContext(ctx, `INSERT INTO ex_fts(ex_fts, rank) VALUES('merge', ?)`, -reclaimMergePages); err != nil {
			return false, fmt.Errorf("合并全文索引: %w", err)
		}
		*merges--
		progressed = true
	}
	if !t.incrementalVacuum {
		// incremental_vacuum is a silent no-op on a database created with
		// auto_vacuum=0; only a full compaction can convert one. Merging the
		// full-text index above still pays off, so stop here rather than earlier.
		return progressed, nil
	}
	var before, after int
	if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&before); err != nil {
		return false, err
	}
	if before == 0 {
		return progressed, nil
	}
	// The budget is a constant and PRAGMA arguments cannot be bound as parameters.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, reclaimChunkPages)); err != nil {
		return false, fmt.Errorf("回收索引空闲页: %w", err)
	}
	if err := conn.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&after); err != nil {
		return false, err
	}
	// Progress, not an empty freelist, is the right stopping condition:
	// incremental_vacuum can only release pages it manages to move to the end of
	// the file, so a residual freelist it cannot shrink is a normal outcome.
	return progressed || after < before, nil
}

// gcBlobs removes blobs that no remaining exchange references. Live references
// come from blob_refs, so collection is one query plus a sweep of the blob
// directory — no exchange body is ever read. Emptied bucket directories are
// removed as well; the previous file-scanning collector deleted only files and
// left the buckets behind permanently. Best-effort: walk errors only skip the
// affected entries. Callers must hold wmu so this never races a concurrent
// record() writing a fresh blob + reference.
func (t *Traffic) gcBlobs() error {
	refs := make(map[string]struct{})
	rows, err := t.db.Query(`SELECT DISTINCT hash FROM blob_refs`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		refs[h] = struct{}{}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := t.legacyBlobRefs(refs); err != nil {
		return err
	}

	root := filepath.Join(t.dir, "_blobs", "sha256")
	var buckets []string
	if err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			if p != root {
				buckets = append(buckets, p)
			}
			return nil
		}
		h := strings.TrimSuffix(d.Name(), ".bin")
		if _, ok := refs[h]; !ok {
			os.Remove(p)
		}
		return nil
	}); err != nil {
		return err
	}
	// Deepest first, so a two-level bucket left by the old layout collapses fully.
	// Remove fails harmlessly on a non-empty directory — exactly the guard needed
	// to avoid deleting a bucket that still holds live blobs.
	sort.Slice(buckets, func(i, j int) bool { return len(buckets[i]) > len(buckets[j]) })
	for _, b := range buckets {
		os.Remove(b)
	}
	return nil
}

// legacyBlobRefs adds hashes referenced by pre-SQLite exchanges, whose bodies are
// still .http files on disk holding "@blob sha256:<hex>" pointers. Without this
// the first collection after the upgrade would delete blobs that history still
// points at. Skipped entirely once no legacy rows remain — the steady state — so
// the tree walk is transitional rather than a permanent cost.
func (t *Traffic) legacyBlobRefs(refs map[string]struct{}) error {
	var n int
	if err := t.db.QueryRow(`SELECT COUNT(*) FROM exchanges WHERE path<>''`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	blobRe := regexp.MustCompile(`@blob sha256:([0-9a-f]{64})`)
	return filepath.WalkDir(t.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			// _blobs/_index/_ca never contain references; skip their subtrees.
			if p != t.dir && strings.HasPrefix(d.Name(), "_") {
				return filepath.SkipDir
			}
			return nil
		}
		if nm := d.Name(); nm != "request.http" && nm != "response.http" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, m := range blobRe.FindAllSubmatch(b, -1) {
			refs[string(m[1])] = struct{}{}
		}
		return nil
	})
}

// query returns one page of exchange metadata filtered by host and/or a url
// substring. Default page size is intentionally small (3) to keep tool results
// lightweight and capped at 10; page is 0-based (page*limit offset).
func (t *Traffic) query(host, contains, bodyContains string, page, limit int) ([]ExchangeMeta, error) {
	if limit <= 0 {
		limit = 3
	}
	if limit > 10 {
		limit = 10
	}
	if page < 0 {
		page = 0
	}
	q := `SELECT id,ts,host,method,url_template,url,status,content_type,resp_len,path FROM exchanges WHERE 1=1`
	args := []any{}
	if host != "" {
		hostName, port, err := normalizeSearchHost(host)
		if err != nil {
			return nil, err
		}
		q += ` AND host=?`
		args = append(args, hostName)
		if port != "" {
			// Recorded rows historically store URL.Hostname() (without the port),
			// so constrain the original URL authority as a compatibility fallback.
			// New and old captures therefore share the same search contract.
			authority := net.JoinHostPort(hostName, port)
			q += ` AND (url LIKE ? OR url LIKE ? OR url LIKE ?)`
			args = append(args,
				"%://"+authority+"/%",
				"%://"+authority+"?%",
				"%://"+authority,
			)
		}
	}
	if contains != "" {
		q += ` AND (url LIKE ? OR url_template LIKE ?)`
		args = append(args, "%"+contains+"%", "%"+contains+"%")
	}
	if b := strings.TrimSpace(bodyContains); b != "" {
		cond, arg, ok := t.ftsFilter(b)
		if !ok {
			if !t.fts {
				return nil, fmt.Errorf("当前实例未启用全文索引，无法按正文搜索")
			}
			return nil, fmt.Errorf("正文搜索关键词至少需要 %d 个字符（当前 %d 个）", minTrigram, utf8.RuneCountInString(b))
		}
		q += ` AND ` + cond
		args = append(args, arg)
	}
	q += ` ORDER BY ts DESC LIMIT ? OFFSET ?`
	args = append(args, limit, page*limit)
	rows, err := t.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExchangeMeta
	for rows.Next() {
		var m ExchangeMeta
		if err := rows.Scan(&m.ID, &m.TS, &m.Host, &m.Method, &m.URLTemplate, &m.URL, &m.Status, &m.ContentType, &m.RespLen, &m.Path); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// normalizeSearchHost accepts the forms agents commonly have at hand while
// keeping the stored host (URL.Hostname()) as the canonical host key. A port,
// when supplied, is applied to the URL authority so captures from different
// services on the same IP cannot be mixed.
func normalizeSearchHost(raw string) (host, port string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", errors.New("host 为必填参数")
	}
	if strings.Contains(raw, "://") {
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Host == "" {
			return "", "", fmt.Errorf("无法解析 host：%q", raw)
		}
		host, port = u.Hostname(), u.Port()
	} else if h, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
		host, port = h, p
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
	} else {
		host = raw
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "", "", fmt.Errorf("无法解析 host：%q", raw)
	}
	if port != "" {
		p, parseErr := strconv.Atoi(port)
		if parseErr != nil || p < 1 || p > 65535 {
			return "", "", fmt.Errorf("端口无效：%q", port)
		}
		port = strconv.Itoa(p)
	}
	return strings.ToLower(host), port, nil
}

// Tools exposes traffic lookup to work agents so they query already-captured
// traffic instead of re-curling the same resource (token + dedup win).
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n... [截断，共 %d 字节；完整在流量文件树] ...", len(s))
}
