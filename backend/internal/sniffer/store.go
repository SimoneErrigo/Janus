package sniffer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
	flowmodel "github.com/SimoneErrigo/Janus/backend/internal/flow"
	_ "modernc.org/sqlite"
)

// packetSelectCols is the standard column list for packet SELECTs.
const packetSelectCols = "id, service_id, session_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, direction, method, url, status, headers, body, body_string, decoded, capture_truncated, matched_rules, flagged, contains_flagid, flag_count_body, flag_count_headers, flag_count_url, matched_flagids, flagid_round, verdict, attack_score, normal_score, score_coverage, score_confidence, classification, score_reasons, analyst_label"

// packetSummaryCols is the slim column list for list-view queries: skips
// body (raw blob), body_string (returned truncated via substr below), and
// matched_flagids JSON. Headers are still selected because the row cell
// preview falls back to body_string substring when URL is empty.
const packetSummaryCols = "id, service_id, session_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, direction, method, url, status, substr(body_string, 1, 80), capture_truncated, matched_rules, flagged, contains_flagid, flag_count_body, flag_count_headers, flag_count_url, flagid_round, verdict, attack_score, normal_score, score_coverage, score_confidence, classification, score_reasons, analyst_label"

// PacketStore handles SQLite persistence for captured packets.
// Uses separate read/write connection pools for WAL-mode concurrency:
// writes (INSERT/UPDATE/DELETE) go through db (single conn),
// reads (SELECT/COUNT) go through rdb (multi-conn pool).
type PacketStore struct {
	db  *sql.DB // writer: single connection for INSERT/UPDATE/DELETE
	rdb *sql.DB // reader: connection pool for SELECT queries (concurrent with writer in WAL mode)

	dbPath   string // path to packets.db (for accurate file-size reporting)
	muChange sync.RWMutex
	onChange func(PacketChangeKind, *Packet)
	onScore  func(ScoreUpdate)

	roundResolver func(time.Time) int

	flowCorrelationWindowSec atomic.Int64

	// Async batched writer for the proxy hot path. Enqueue() pushes here;
	// a single goroutine drains and writes batches via multi-row INSERT.
	queue  chan batchItem
	stopCh chan struct{}
	doneCh chan struct{}

	lifecycleMu   sync.RWMutex
	writerStopped bool
	stopOnce      sync.Once
	closeOnce     sync.Once
	closeErr      error
	queueDropped  atomic.Uint64
	writerErrors  atomic.Uint64
}

// batchItem carries a packet and any alerts that must be linked to it.
// The alerts have PacketID unset; the writer fills it in once the packet ID is known.
type batchItem struct {
	pkt       *Packet
	alerts    []*Alert
	flushDone chan struct{}
}

const (
	packetQueueSize    = 8192
	packetBatchMax     = 64
	packetBatchFlushMs = 25

	// Internal writes are serialized by the one-connection writer pool. This
	// timeout is therefore only a guard for short-lived external/recovery locks;
	// keeping it bounded prevents a stalled writer from exhausting the capture
	// queue under competition load.
	sqliteBusyTimeoutMS      = 5_000
	sqliteCacheSizeKiB       = 32_000
	sqliteWriterMaxOpenConns = 1
	sqliteReaderMaxOpenConns = 4
)

var (
	ErrPacketStoreClosed = errors.New("packet store is closed")
	ErrPacketQueueFull   = errors.New("packet capture queue is full")
)

// NewPacketStore opens (or creates) the SQLite database at dataDir/packets.db.
func NewPacketStore(dataDir string) (*PacketStore, error) {
	dbPath, err := filepath.Abs(filepath.Join(dataDir, "packets.db"))
	if err != nil {
		return nil, fmt.Errorf("resolving sqlite path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("creating sqlite data directory: %w", err)
	}

	writerDSN := sqliteFileDSN(dbPath, "rwc",
		fmt.Sprintf("busy_timeout(%d)", sqliteBusyTimeoutMS),
		"journal_mode(WAL)",
		"synchronous(NORMAL)",
		fmt.Sprintf("cache_size(-%d)", sqliteCacheSizeKiB),
	)

	// Writer connection: single conn to serialize INSERTs/UPDATEs/DELETEs
	db, err := sql.Open("sqlite", writerDSN)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite writer: %w", err)
	}
	db.SetMaxOpenConns(sqliteWriterMaxOpenConns)
	db.SetMaxIdleConns(sqliteWriterMaxOpenConns)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting sqlite writer: %w", err)
	}
	if err := verifySQLiteWriter(db); err != nil {
		db.Close()
		return nil, err
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating sqlite: %w", err)
	}

	// Reader connection pool: multiple conns for concurrent SELECTs
	// WAL mode allows concurrent readers even while a write is in progress. Open
	// it only after the writer has created/migrated the DB and enabled WAL, since
	// a genuinely read-only URI cannot initialize either of those things.
	readerDSN := sqliteFileDSN(dbPath, "ro",
		fmt.Sprintf("busy_timeout(%d)", sqliteBusyTimeoutMS),
		"query_only(ON)",
		fmt.Sprintf("cache_size(-%d)", sqliteCacheSizeKiB),
	)
	rdb, err := sql.Open("sqlite", readerDSN)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("opening sqlite reader: %w", err)
	}
	rdb.SetMaxOpenConns(sqliteReaderMaxOpenConns)
	rdb.SetMaxIdleConns(sqliteReaderMaxOpenConns)
	if err := rdb.Ping(); err != nil {
		db.Close()
		rdb.Close()
		return nil, fmt.Errorf("connecting sqlite reader: %w", err)
	}
	if err := verifySQLiteReader(rdb); err != nil {
		db.Close()
		rdb.Close()
		return nil, err
	}

	ps := &PacketStore{
		db:     db,
		rdb:    rdb,
		dbPath: dbPath,
		queue:  make(chan batchItem, packetQueueSize),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	ps.flowCorrelationWindowSec.Store(120)
	log.Printf("SQLite packet store ready (WAL, busy_timeout=%dms, writer_pool=%d, reader_pool=%d)",
		sqliteBusyTimeoutMS, sqliteWriterMaxOpenConns, sqliteReaderMaxOpenConns)
	go ps.runBatchWriter()
	return ps, nil
}

// sqliteFileDSN builds a real SQLite URI. modernc.org/sqlite only forwards
// standard URI options such as mode=ro to SQLite when the DSN starts with
// "file:"; driver-level PRAGMAs must be supplied through repeated _pragma
// parameters. Using net/url also keeps paths containing spaces, '#', or '?'
// unambiguous.
func sqliteFileDSN(dbPath, mode string, pragmas ...string) string {
	uriPath := filepath.ToSlash(dbPath)
	if filepath.VolumeName(dbPath) != "" && !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := &url.URL{Scheme: "file", Path: uriPath}
	q := u.Query()
	q.Set("mode", mode)
	for _, pragma := range pragmas {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func verifySQLiteWriter(db *sql.DB) error {
	if got := db.Stats().MaxOpenConnections; got != sqliteWriterMaxOpenConns {
		return fmt.Errorf("sqlite writer pool has %d max connections, want %d", got, sqliteWriterMaxOpenConns)
	}
	readOnly, err := sqliteMainIsReadOnly(db)
	if err != nil {
		return fmt.Errorf("verifying sqlite writer access mode: %w", err)
	}
	if readOnly {
		return fmt.Errorf("sqlite writer connection is read-only")
	}
	if err := expectSQLitePragmaString(db, "journal_mode", "wal"); err != nil {
		return fmt.Errorf("verifying sqlite writer WAL mode: %w", err)
	}
	if err := expectSQLitePragmaInt(db, "busy_timeout", sqliteBusyTimeoutMS); err != nil {
		return fmt.Errorf("verifying sqlite writer busy timeout: %w", err)
	}
	if err := expectSQLitePragmaInt(db, "synchronous", 1); err != nil { // NORMAL
		return fmt.Errorf("verifying sqlite writer synchronous mode: %w", err)
	}
	if err := expectSQLitePragmaInt(db, "cache_size", -sqliteCacheSizeKiB); err != nil {
		return fmt.Errorf("verifying sqlite writer cache size: %w", err)
	}
	return nil
}

func verifySQLiteReader(db *sql.DB) error {
	if got := db.Stats().MaxOpenConnections; got != sqliteReaderMaxOpenConns {
		return fmt.Errorf("sqlite reader pool has %d max connections, want %d", got, sqliteReaderMaxOpenConns)
	}
	readOnly, err := sqliteMainIsReadOnly(db)
	if err != nil {
		return fmt.Errorf("verifying sqlite reader access mode: %w", err)
	}
	if !readOnly {
		return fmt.Errorf("sqlite reader connection is not read-only")
	}
	if err := expectSQLitePragmaString(db, "journal_mode", "wal"); err != nil {
		return fmt.Errorf("verifying sqlite reader WAL mode: %w", err)
	}
	if err := expectSQLitePragmaInt(db, "busy_timeout", sqliteBusyTimeoutMS); err != nil {
		return fmt.Errorf("verifying sqlite reader busy timeout: %w", err)
	}
	if err := expectSQLitePragmaInt(db, "query_only", 1); err != nil {
		return fmt.Errorf("verifying sqlite reader query-only mode: %w", err)
	}
	if err := expectSQLitePragmaInt(db, "cache_size", -sqliteCacheSizeKiB); err != nil {
		return fmt.Errorf("verifying sqlite reader cache size: %w", err)
	}
	return nil
}

func sqliteMainIsReadOnly(db *sql.DB) (bool, error) {
	conn, err := db.Conn(context.Background())
	if err != nil {
		return false, err
	}
	defer conn.Close()

	var readOnly bool
	err = conn.Raw(func(driverConn any) error {
		checker, ok := driverConn.(interface {
			IsReadOnly(string) (bool, error)
		})
		if !ok {
			return fmt.Errorf("sqlite driver connection %T does not expose IsReadOnly", driverConn)
		}
		var checkErr error
		readOnly, checkErr = checker.IsReadOnly("main")
		return checkErr
	})
	return readOnly, err
}

func expectSQLitePragmaString(db *sql.DB, name, want string) error {
	var got string
	if err := db.QueryRow("PRAGMA " + name).Scan(&got); err != nil {
		return err
	}
	if !strings.EqualFold(got, want) {
		return fmt.Errorf("PRAGMA %s is %q, want %q", name, got, want)
	}
	return nil
}

func expectSQLitePragmaInt(db *sql.DB, name string, want int) error {
	var got int
	if err := db.QueryRow("PRAGMA " + name).Scan(&got); err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("PRAGMA %s is %d, want %d", name, got, want)
	}
	return nil
}

func (s *PacketStore) SetFlowCorrelationWindowSec(sec int) {
	if sec <= 0 {
		sec = 120
	}
	s.flowCorrelationWindowSec.Store(int64(sec))
}

func (s *PacketStore) flowCorrelationWindow() time.Duration {
	sec := s.flowCorrelationWindowSec.Load()
	if sec <= 0 {
		sec = 120
	}
	return time.Duration(sec) * time.Second
}

// SetRoundResolver annotates packets read from storage with the scoreboard
// round derived from their timestamp. When unset, views fall back to
// flagid_round for backward compatibility.
func (s *PacketStore) SetRoundResolver(fn func(time.Time) int) {
	s.roundResolver = fn
}

func (s *PacketStore) annotateRound(p *Packet) {
	if p == nil || s.roundResolver == nil {
		return
	}
	p.Round = s.roundResolver(p.Timestamp)
	if p.Round == 0 && p.FlagIDRound > 0 {
		p.Round = p.FlagIDRound
	}
}

// SetPacketChangeListener is called when new packets are inserted or metadata is bulk-updated
// (e.g. flag-ID backfill). The callback must be non-blocking; it is invoked synchronously from Insert.
func (s *PacketStore) SetPacketChangeListener(fn func(PacketChangeKind, *Packet)) {
	s.muChange.Lock()
	defer s.muChange.Unlock()
	s.onChange = fn
}

func (s *PacketStore) SetScoreChangeListener(fn func(ScoreUpdate)) {
	s.muChange.Lock()
	defer s.muChange.Unlock()
	s.onScore = fn
}

func (s *PacketStore) emitChange(kind PacketChangeKind, pkt *Packet) {
	s.muChange.RLock()
	fn := s.onChange
	s.muChange.RUnlock()
	if fn == nil {
		return
	}
	fn(kind, pkt)
}

func (s *PacketStore) emitScoreChange(update ScoreUpdate) bool {
	s.muChange.RLock()
	fn := s.onScore
	s.muChange.RUnlock()
	if fn != nil {
		fn(update)
		return true
	}
	return false
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS packets (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id    TEXT    NOT NULL,
			session_id    TEXT    NOT NULL DEFAULT '',
			timestamp     TEXT    NOT NULL,
			src_ip        TEXT    NOT NULL,
			src_port      INTEGER NOT NULL,
			dst_ip        TEXT    NOT NULL,
			dst_port      INTEGER NOT NULL,
			protocol      TEXT    NOT NULL,
			direction     TEXT    NOT NULL,
			method        TEXT    NOT NULL DEFAULT '',
			url           TEXT    NOT NULL DEFAULT '',
			status        INTEGER NOT NULL DEFAULT 0,
			headers       TEXT    NOT NULL DEFAULT '{}',
			body          BLOB,
			body_string   TEXT    NOT NULL DEFAULT '',
			decoded       TEXT    NOT NULL DEFAULT '{}',
			capture_truncated INTEGER NOT NULL DEFAULT 0,
			matched_rules    TEXT    NOT NULL DEFAULT '[]',
			flagged          INTEGER NOT NULL DEFAULT 0,
				contains_flagid  INTEGER NOT NULL DEFAULT 0,
				flag_count_body INTEGER NOT NULL DEFAULT 0,
				flag_count_headers INTEGER NOT NULL DEFAULT 0,
				flag_count_url INTEGER NOT NULL DEFAULT 0,
			flagid_scanned_round INTEGER NOT NULL DEFAULT 0,
			has_drop_match   INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_packets_timestamp  ON packets(timestamp);
		CREATE INDEX IF NOT EXISTS idx_packets_dst_ip     ON packets(dst_ip);
		CREATE INDEX IF NOT EXISTS idx_packets_protocol   ON packets(protocol);
	`)
	if err != nil {
		return err
	}

	// Add columns if upgrading from an older schema
	for _, col := range []string{
		"ALTER TABLE packets ADD COLUMN matched_rules TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE packets ADD COLUMN flagged INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN session_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE packets ADD COLUMN contains_flagid INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN flag_count_body INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN flag_count_headers INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN flag_count_url INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN matched_flagids TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE packets ADD COLUMN flagid_round INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN flagid_scanned_round INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN has_drop_match INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN verdict TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE packets ADD COLUMN capture_truncated INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN decoded TEXT NOT NULL DEFAULT '{}'",
		"ALTER TABLE packets ADD COLUMN attack_score INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN normal_score INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN score_coverage INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN score_confidence INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN classification TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE packets ADD COLUMN score_reasons TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE packets ADD COLUMN analyst_label TEXT NOT NULL DEFAULT ''",
		// inserted_at tracks when the row was added to *this* DB, distinct
		// from the wire timestamp. Cleanup-by-age uses it so imports of old
		// PCAPs aren't immediately wiped just because their capture clock
		// is in the past.
		"ALTER TABLE packets ADD COLUMN inserted_at TEXT NOT NULL DEFAULT ''",
	} {
		if _, err := db.Exec(col); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return fmt.Errorf("migrating packets column: %w", err)
		}
	}

	// One-time backfills and indexes for columns added above. Unlike duplicate
	// ALTER errors, failures here indicate a damaged/unwritable DB and must stop
	// startup instead of leaving a partially migrated store.
	for _, statement := range []string{
		"UPDATE packets SET inserted_at = timestamp WHERE inserted_at = ''",
		`UPDATE packets SET timestamp = CASE
			WHEN length(timestamp) = 20 THEN substr(timestamp, 1, 19) || '.000000000Z'
			ELSE substr(timestamp, 1, length(timestamp) - 1) || substr('000000000', 1, 30 - length(timestamp)) || 'Z'
		END WHERE substr(timestamp, -1) = 'Z' AND length(timestamp) BETWEEN 20 AND 29
			AND (length(timestamp) = 20 OR substr(timestamp, 20, 1) = '.')`,
		`UPDATE packets SET inserted_at = CASE
			WHEN length(inserted_at) = 20 THEN substr(inserted_at, 1, 19) || '.000000000Z'
			ELSE substr(inserted_at, 1, length(inserted_at) - 1) || substr('000000000', 1, 30 - length(inserted_at)) || 'Z'
		END WHERE substr(inserted_at, -1) = 'Z' AND length(inserted_at) BETWEEN 20 AND 29
			AND (length(inserted_at) = 20 OR substr(inserted_at, 20, 1) = '.')`,
		"UPDATE packets SET flagid_scanned_round = flagid_round WHERE flagid_scanned_round = 0 AND flagid_round > 0",
		// Old schemas only knew a boolean. Keep an explicit conservative lower
		// bound; all newly captured rows persist exact component counts.
		"UPDATE packets SET flag_count_body = 1 WHERE flagged = 1 AND flag_count_body + flag_count_headers + flag_count_url = 0",
		"CREATE INDEX IF NOT EXISTS idx_packets_session_id ON packets(session_id)",
		"CREATE INDEX IF NOT EXISTS idx_packets_service_ts ON packets(service_id, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_packets_flagged_ts ON packets(flagged, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_packets_contains_flagid_ts ON packets(contains_flagid, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_packets_drop_ts ON packets(has_drop_match, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_packets_direction_ts ON packets(direction, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_packets_src_ts ON packets(src_ip, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_packets_flagid_round ON packets(flagid_round, timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_packets_flagid_scanned_round ON packets(flagid_scanned_round, timestamp)",
		"CREATE INDEX IF NOT EXISTS idx_packets_inserted_at ON packets(inserted_at)",
		"CREATE INDEX IF NOT EXISTS idx_packets_classification_ts ON packets(classification, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_packets_attack_score_ts ON packets(attack_score, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_packets_analyst_label_ts ON packets(analyst_label, timestamp DESC)",
		// These single-column indexes are left-prefix duplicates of the compound
		// timestamp indexes above. Removing them cuts packet index maintenance by
		// six B-trees while preserving their lookup paths.
		"DROP INDEX IF EXISTS idx_packets_service_id",
		"DROP INDEX IF EXISTS idx_packets_src_ip",
		"DROP INDEX IF EXISTS idx_packets_flagged",
		"DROP INDEX IF EXISTS idx_packets_contains_flagid",
		"DROP INDEX IF EXISTS idx_packets_has_drop_match",
		"DROP INDEX IF EXISTS idx_packets_backfill",
	} {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("finishing packet migration: %w", err)
		}
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS baseline_signatures (
		service_id TEXT NOT NULL, signature TEXT NOT NULL, rounds TEXT NOT NULL DEFAULT '[]',
		PRIMARY KEY(service_id, signature)
	);
	CREATE TABLE IF NOT EXISTS baseline_meta (
		key TEXT PRIMARY KEY, value TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS baseline_snapshot_meta (
		epoch TEXT PRIMARY KEY,
		definition TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS baseline_snapshot_signatures (
		epoch TEXT NOT NULL,
		service_id TEXT NOT NULL,
		signature TEXT NOT NULL,
		rounds TEXT NOT NULL DEFAULT '[]',
		PRIMARY KEY(epoch, service_id, signature)
	)`)
	if err != nil {
		return err
	}
	// Preserve the legacy single active baseline as the first versioned
	// snapshot. The INSERTs are idempotent and make upgrades crash-safe.
	now := CanonicalTimestamp(time.Now())
	if _, err := db.Exec(`INSERT OR IGNORE INTO baseline_snapshot_meta(epoch, definition, created_at, updated_at)
		SELECT value, '', ?, ? FROM baseline_meta WHERE key = 'epoch'`, now, now); err != nil {
		return fmt.Errorf("migrating baseline snapshot metadata: %w", err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO baseline_snapshot_signatures(epoch, service_id, signature, rounds)
		SELECT m.value, s.service_id, s.signature, s.rounds
		FROM baseline_signatures s CROSS JOIN baseline_meta m WHERE m.key = 'epoch'`); err != nil {
		return fmt.Errorf("migrating baseline snapshot signatures: %w", err)
	}

	// Backfill existing rows once after migration.
	// A row is considered dropped if any matched rule has action drop/both.
	if _, err := db.Exec("UPDATE packets SET has_drop_match = CASE WHEN (matched_rules LIKE '%\"action\":\"drop\"%' OR matched_rules LIKE '%\"action\":\"both\"%') THEN 1 ELSE 0 END WHERE has_drop_match = 0"); err != nil {
		return fmt.Errorf("backfilling packet drops: %w", err)
	}
	// A response was already forwarded by the legacy pipeline before its rules
	// were evaluated, so it must never be migrated as an actual drop.
	if _, err := db.Exec("UPDATE packets SET has_drop_match = 0 WHERE direction = 'response'"); err != nil {
		return fmt.Errorf("normalizing response verdicts: %w", err)
	}

	// Step 6: alerts table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS alerts (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			packet_id       INTEGER NOT NULL,
			rule_id         TEXT    NOT NULL,
			service_id      TEXT    NOT NULL,
			src_ip          TEXT    NOT NULL,
			timestamp       TEXT    NOT NULL,
			pattern_matched TEXT    NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_alerts_service_id ON alerts(service_id);
		CREATE INDEX IF NOT EXISTS idx_alerts_rule_id    ON alerts(rule_id);
		CREATE INDEX IF NOT EXISTS idx_alerts_timestamp  ON alerts(timestamp);
		CREATE INDEX IF NOT EXISTS idx_alerts_src_ip     ON alerts(src_ip);
		CREATE INDEX IF NOT EXISTS idx_alerts_packet_id  ON alerts(packet_id);
	`)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE alerts SET timestamp = CASE
		WHEN length(timestamp) = 20 THEN substr(timestamp, 1, 19) || '.000000000Z'
		ELSE substr(timestamp, 1, length(timestamp) - 1) || substr('000000000', 1, 30 - length(timestamp)) || 'Z'
	END WHERE substr(timestamp, -1) = 'Z' AND length(timestamp) BETWEEN 20 AND 29
		AND (length(timestamp) = 20 OR substr(timestamp, 20, 1) = '.')`); err != nil {
		return fmt.Errorf("normalizing alert timestamps: %w", err)
	}

	// Step 21: saved flows table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS saved_flows (
			id               INTEGER PRIMARY KEY AUTOINCREMENT,
			name             TEXT    NOT NULL,
			anchor_packet_id INTEGER NOT NULL,
			packet_ids       TEXT    NOT NULL DEFAULT '[]',
			created_by       TEXT    NOT NULL DEFAULT '',
			created_at       TEXT    NOT NULL,
			notes            TEXT    NOT NULL DEFAULT ''
		);
	`)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`UPDATE saved_flows SET created_at = CASE
		WHEN length(created_at) = 20 THEN substr(created_at, 1, 19) || '.000000000Z'
		ELSE substr(created_at, 1, length(created_at) - 1) || substr('000000000', 1, 30 - length(created_at)) || 'Z'
	END WHERE substr(created_at, -1) = 'Z' AND length(created_at) BETWEEN 20 AND 29
		AND (length(created_at) = 20 OR substr(created_at, 20, 1) = '.')`); err != nil {
		return fmt.Errorf("normalizing saved-flow timestamps: %w", err)
	}

	// Snapshot of full packet data per saved flow — survives packet purges so
	// pinned flows remain inspectable after the packets table is wiped. The
	// secondary index on packet_id supports GetPacketByIDFromSnapshots so the
	// gRPC/custom-protocol decode endpoints can resolve a snapshotted packet
	// without scanning the whole table.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS saved_flow_packets (
			saved_flow_id INTEGER NOT NULL,
			ordinal       INTEGER NOT NULL,
			packet_id     INTEGER NOT NULL,
			data          BLOB    NOT NULL,
			PRIMARY KEY (saved_flow_id, ordinal)
		);
		CREATE INDEX IF NOT EXISTS idx_sfp_flow ON saved_flow_packets(saved_flow_id);
		CREATE INDEX IF NOT EXISTS idx_sfp_packet ON saved_flow_packets(packet_id);
	`)
	if err != nil {
		return err
	}

	return nil
}

func isSQLiteBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "SQLITE_BUSY")
}

// autoFillBodyString populates p.BodyString with the UTF-8 view of the body
// when the body is valid UTF-8 and the caller hasn't already set it. Bodies
// served with a binary Content-Type (gRPC, protobuf, octet-stream, …) are
// left empty even when their bytes happen to be UTF-8 decodable: surfacing
// raw protobuf wire bytes as a string only produces unreadable noise and
// hides the structured "Decoded" view in the UI.
func autoFillBodyString(p *Packet) {
	if p == nil || len(p.Body) == 0 || p.BodyString != "" {
		return
	}
	if isBinaryContentType(p.Headers) {
		return
	}
	if utf8.Valid(p.Body) {
		p.BodyString = string(p.Body)
	}
}

// ensurePacketVerdict reconstructs a conservative verdict for legacy callers
// and rows. New data-plane paths set Verdict explicitly before persistence.
func ensurePacketVerdict(p *Packet) {
	if p == nil || p.Verdict.Outcome != "" {
		return
	}
	hasDrop, hasAlert := false, false
	ruleIDs := make([]string, 0, len(p.MatchedRules))
	for _, rule := range p.MatchedRules {
		ruleIDs = append(ruleIDs, rule.ID)
		switch rule.Action {
		case "drop":
			hasDrop = true
		case "both":
			hasDrop, hasAlert = true, true
		case "alert":
			hasAlert = true
		}
	}
	phase := string(p.Direction)
	switch {
	case hasDrop && p.Direction == DirectionRequest:
		p.Verdict = flowmodel.Verdict{Decision: flowmodel.DecisionDrop, Outcome: flowmodel.OutcomeDropped, Phase: phase, Applied: true, RuleIDs: ruleIDs}
	case hasDrop:
		p.Verdict = flowmodel.Verdict{Decision: flowmodel.DecisionDrop, Outcome: flowmodel.OutcomeWouldDrop, Phase: phase, Applied: false, RuleIDs: ruleIDs}
	case hasAlert:
		p.Verdict = flowmodel.Verdict{Decision: flowmodel.DecisionAlert, Outcome: flowmodel.OutcomeForwarded, Phase: phase, Applied: true, RuleIDs: ruleIDs}
	default:
		p.Verdict = flowmodel.Forwarded(phase)
	}
}

// isBinaryContentType reports whether the headers declare a body format that
// shouldn't be rendered as text (gRPC, protobuf, raw octets). The check is
// case-insensitive and tolerant of "type/subtype; charset=…" suffixes.
func isBinaryContentType(headers map[string]string) bool {
	if len(headers) == 0 {
		return false
	}
	var ct string
	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") {
			ct = v
			break
		}
	}
	if ct == "" {
		return false
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case strings.HasPrefix(ct, "application/grpc"),
		strings.HasPrefix(ct, "application/protobuf"),
		strings.HasPrefix(ct, "application/x-protobuf"),
		strings.HasPrefix(ct, "application/octet-stream"):
		return true
	}
	return false
}

// Insert stores a packet in the database.
func (s *PacketStore) Insert(p *Packet) error {
	if p == nil {
		return nil
	}
	autoFillBodyString(p)
	ensurePacketVerdict(p)

	headersJSON, err := json.Marshal(p.Headers)
	if err != nil {
		headersJSON = []byte("{}")
	}

	matchedRulesJSON, err := json.Marshal(p.MatchedRules)
	if err != nil {
		matchedRulesJSON = []byte("[]")
	}
	decodedJSON, err := json.Marshal(p.Decoded)
	if err != nil {
		decodedJSON = []byte("{}")
	}

	flaggedInt := 0
	if p.Flagged {
		flaggedInt = 1
	}
	containsFlagIDInt := 0
	if p.ContainsFlagID {
		containsFlagIDInt = 1
	}
	captureTruncatedInt := 0
	if p.CaptureTruncated {
		captureTruncatedInt = 1
	}
	hasDropMatchInt := 0
	if p.Verdict.Outcome == flowmodel.OutcomeDropped {
		hasDropMatchInt = 1
	}
	verdictJSON, err := json.Marshal(p.Verdict)
	if err != nil {
		verdictJSON = []byte("{}")
	}

	if p.MatchedFlagIDs == nil {
		p.MatchedFlagIDs = []string{}
	}
	matchedFlagIDsJSON, err := json.Marshal(p.MatchedFlagIDs)
	if err != nil {
		matchedFlagIDsJSON = []byte("[]")
	}

	insertedAt := CanonicalTimestamp(time.Now())
	res, err := s.db.Exec(`
		INSERT INTO packets (service_id, session_id, timestamp, src_ip, src_port, dst_ip, dst_port,
			protocol, direction, method, url, status, headers, body, body_string, decoded, capture_truncated,
				matched_rules, flagged, contains_flagid, flag_count_body, flag_count_headers, flag_count_url, matched_flagids, flagid_round, has_drop_match,
				flagid_scanned_round, inserted_at, verdict)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ServiceID, p.SessionID,
		CanonicalTimestamp(p.Timestamp),
		p.SrcIP, p.SrcPort,
		p.DstIP, p.DstPort,
		p.Protocol, p.Direction,
		p.Method, p.URL, p.Status,
		string(headersJSON),
		p.Body, p.BodyString, string(decodedJSON), captureTruncatedInt,
		string(matchedRulesJSON), flaggedInt, containsFlagIDInt,
		p.FlagCountBody, p.FlagCountHeaders, p.FlagCountURL,
		string(matchedFlagIDsJSON), p.FlagIDRound, hasDropMatchInt, p.FlagIDRound,
		insertedAt, string(verdictJSON),
	)
	if err != nil {
		return fmt.Errorf("inserting packet: %w", err)
	}

	id, _ := res.LastInsertId()
	p.ID = id
	s.annotateRound(p)
	s.emitChange(PacketChangeInsert, p)
	return nil
}

// Enqueue submits a packet (and any linked alerts whose PacketID will be filled
// in by the writer) to the async batched writer. It never waits for SQLite:
// under sustained overload capture metadata is dropped rather than delaying
// checker traffic through the proxy.
func (s *PacketStore) Enqueue(pkt *Packet, alerts []*Alert) error {
	if pkt == nil {
		return nil
	}
	autoFillBodyString(pkt)
	if pkt.MatchedFlagIDs == nil {
		pkt.MatchedFlagIDs = []string{}
	}
	if pkt.MatchedRules == nil {
		pkt.MatchedRules = []MatchedRuleInfo{}
	}
	ensurePacketVerdict(pkt)
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()
	if s.writerStopped {
		return ErrPacketStoreClosed
	}
	select {
	case s.queue <- batchItem{pkt: pkt, alerts: alerts}:
		return nil
	default:
		s.queueDropped.Add(1)
		return ErrPacketQueueFull
	}
}

// Flush waits until every packet accepted before this call has reached the
// database. The marker shares the packet queue, so it is an ordering barrier
// without stopping the writer or blocking the proxy's Enqueue hot path.
func (s *PacketStore) Flush(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})

	// Keep Drain from stopping the writer between the lifecycle check and the
	// marker enqueue. Waiting for queue capacity here is safe: Flush is a control
	// plane operation, whereas packet Enqueue remains non-blocking.
	s.lifecycleMu.RLock()
	if s.writerStopped {
		s.lifecycleMu.RUnlock()
		return ErrPacketStoreClosed
	}
	select {
	case s.queue <- batchItem{flushDone: done}:
		s.lifecycleMu.RUnlock()
	case <-ctx.Done():
		s.lifecycleMu.RUnlock()
		return ctx.Err()
	}

	select {
	case <-done:
		return nil
	case <-s.doneCh:
		return ErrPacketStoreClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// WriterStats exposes bounded capture degradation without putting metrics on
// the forwarding hot path.
func (s *PacketStore) WriterStats() (queueDropped, writerErrors uint64) {
	return s.queueDropped.Load(), s.writerErrors.Load()
}

func (s *PacketStore) runBatchWriter() {
	defer close(s.doneCh)
	flushPeriod := time.Duration(packetBatchFlushMs) * time.Millisecond
	ticker := time.NewTicker(flushPeriod)
	defer ticker.Stop()

	batch := make([]batchItem, 0, packetBatchMax)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.flushBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case <-s.stopCh:
			// Drain remaining items before exiting
			for {
				select {
				case it := <-s.queue:
					if it.flushDone != nil {
						flush()
						close(it.flushDone)
						continue
					}
					batch = append(batch, it)
					if len(batch) >= packetBatchMax {
						flush()
					}
				default:
					flush()
					return
				}
			}
		case it := <-s.queue:
			if it.flushDone != nil {
				flush()
				close(it.flushDone)
				continue
			}
			batch = append(batch, it)
			if len(batch) >= packetBatchMax {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// flushBatch inserts a batch of packets in a single multi-row INSERT, then
// inserts any linked alerts in a second multi-row INSERT. Falls back to
// per-row inserts on error.
func (s *PacketStore) flushBatch(batch []batchItem) {
	if len(batch) == 0 {
		return
	}

	// --- Build packet INSERT ---
	const packetCols = 29
	rowPlaceholder := "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
	placeholders := make([]string, len(batch))
	args := make([]interface{}, 0, len(batch)*packetCols)
	insertedAt := CanonicalTimestamp(time.Now())
	for i, it := range batch {
		placeholders[i] = rowPlaceholder
		p := it.pkt

		headersJSON, err := json.Marshal(p.Headers)
		if err != nil {
			headersJSON = []byte("{}")
		}
		matchedRulesJSON, err := json.Marshal(p.MatchedRules)
		if err != nil {
			matchedRulesJSON = []byte("[]")
		}
		decodedJSON, err := json.Marshal(p.Decoded)
		if err != nil {
			decodedJSON = []byte("{}")
		}
		matchedFlagIDsJSON, err := json.Marshal(p.MatchedFlagIDs)
		if err != nil {
			matchedFlagIDsJSON = []byte("[]")
		}
		ensurePacketVerdict(p)
		verdictJSON, err := json.Marshal(p.Verdict)
		if err != nil {
			verdictJSON = []byte("{}")
		}

		flaggedInt := 0
		if p.Flagged {
			flaggedInt = 1
		}
		containsFlagIDInt := 0
		if p.ContainsFlagID {
			containsFlagIDInt = 1
		}
		captureTruncatedInt := 0
		if p.CaptureTruncated {
			captureTruncatedInt = 1
		}
		hasDropMatchInt := 0
		if p.Verdict.Outcome == flowmodel.OutcomeDropped {
			hasDropMatchInt = 1
		}

		args = append(args,
			p.ServiceID, p.SessionID,
			CanonicalTimestamp(p.Timestamp),
			p.SrcIP, p.SrcPort,
			p.DstIP, p.DstPort,
			p.Protocol, p.Direction,
			p.Method, p.URL, p.Status,
			string(headersJSON),
			p.Body, p.BodyString, string(decodedJSON), captureTruncatedInt,
			string(matchedRulesJSON), flaggedInt, containsFlagIDInt,
			p.FlagCountBody, p.FlagCountHeaders, p.FlagCountURL,
			string(matchedFlagIDsJSON), p.FlagIDRound, hasDropMatchInt, p.FlagIDRound,
			insertedAt, string(verdictJSON),
		)
	}

	query := `INSERT INTO packets (service_id, session_id, timestamp, src_ip, src_port, dst_ip, dst_port,
		protocol, direction, method, url, status, headers, body, body_string, decoded, capture_truncated,
			matched_rules, flagged, contains_flagid, flag_count_body, flag_count_headers, flag_count_url, matched_flagids, flagid_round, has_drop_match,
		flagid_scanned_round, inserted_at, verdict)
		VALUES ` + strings.Join(placeholders, ",")

	res, err := s.db.Exec(query, args...)
	if err != nil {
		// The connection-level busy handler has already waited for the bounded
		// timeout. Retrying every row would multiply that delay by the batch size
		// and starve the capture queue, so only data-specific failures use the
		// row-by-row salvage path.
		if isSQLiteBusy(err) {
			s.writerErrors.Add(uint64(len(batch)))
			log.Printf("packet writer: batch insert timed out waiting for SQLite; dropped %d capture row(s): %v", len(batch), err)
			return
		}
		// Batch failed — fall back to one-by-one Insert (and InsertAlert) so we
		// don't drop captures wholesale.
		failures := 0
		for _, it := range batch {
			if ierr := s.Insert(it.pkt); ierr != nil {
				failures++
				continue
			}
			for _, a := range it.alerts {
				a.PacketID = it.pkt.ID
				if aerr := s.InsertAlert(a); aerr != nil {
					failures++
				}
			}
		}
		if failures > 0 {
			s.writerErrors.Add(uint64(failures))
			log.Printf("packet writer: batch insert failed (%v); %d fallback row(s) also failed", err, failures)
		}
		return
	}

	lastID, _ := res.LastInsertId()
	firstID := lastID - int64(len(batch)) + 1
	for i, it := range batch {
		it.pkt.ID = firstID + int64(i)
	}

	// --- Build alerts INSERT ---
	var alertPlaceholders []string
	var alertArgs []interface{}
	for _, it := range batch {
		for _, a := range it.alerts {
			a.PacketID = it.pkt.ID
			alertPlaceholders = append(alertPlaceholders, "(?,?,?,?,?,?)")
			alertArgs = append(alertArgs,
				a.PacketID, a.RuleID, a.ServiceID, a.SrcIP,
				CanonicalTimestamp(a.Timestamp),
				a.PatternMatched,
			)
		}
	}
	if len(alertPlaceholders) > 0 {
		alertQuery := `INSERT INTO alerts (packet_id, rule_id, service_id, src_ip, timestamp, pattern_matched) VALUES ` +
			strings.Join(alertPlaceholders, ",")
		if _, err := s.db.Exec(alertQuery, alertArgs...); err != nil {
			if isSQLiteBusy(err) {
				s.writerErrors.Add(uint64(len(alertPlaceholders)))
				log.Printf("packet writer: alert batch timed out waiting for SQLite; dropped %d alert row(s): %v", len(alertPlaceholders), err)
			} else {
				// Best-effort retry per-row so we don't lose alerts on a single bad input.
				failures := 0
				for _, it := range batch {
					for _, a := range it.alerts {
						if aerr := s.InsertAlert(a); aerr != nil {
							failures++
						}
					}
				}
				if failures > 0 {
					s.writerErrors.Add(uint64(failures))
					log.Printf("packet writer: alert batch insert failed (%v); %d fallback row(s) also failed", err, failures)
				}
			}
		}
	}

	// --- Notify SSE for each newly-inserted packet ---
	for _, it := range batch {
		s.annotateRound(it.pkt)
		s.emitChange(PacketChangeInsert, it.pkt)
	}
}

// UpdateFlowScore stores one deterministic classification on every packet in
// the same scored flow. Scoring remains metadata-only and never affects the
// forwarding verdict.
func (s *PacketStore) UpdateFlowScore(packetIDs []int64, score FlowScore) error {
	if len(packetIDs) == 0 {
		return nil
	}
	reasons, err := json.Marshal(score.Reasons)
	if err != nil {
		return fmt.Errorf("encoding score reasons: %w", err)
	}

	const chunkSize = 256
	for start := 0; start < len(packetIDs); start += chunkSize {
		end := start + chunkSize
		if end > len(packetIDs) {
			end = len(packetIDs)
		}
		ids := packetIDs[start:end]
		marks := make([]string, len(ids))
		args := make([]any, 0, 6+len(ids))
		args = append(args, score.Attack, score.Normal, score.Coverage, score.Confidence, score.Classification, string(reasons))
		for i, id := range ids {
			marks[i] = "?"
			args = append(args, id)
		}
		query := `UPDATE packets SET attack_score = ?, normal_score = ?, score_coverage = ?,
			score_confidence = ?, classification = ?, score_reasons = ? WHERE id IN (` + strings.Join(marks, ",") + `)`
		if _, err := s.db.Exec(query, args...); err != nil {
			return fmt.Errorf("updating flow score: %w", err)
		}
	}
	if !s.emitScoreChange(NewScoreUpdate(packetIDs, score)) {
		s.emitChange(PacketChangeMetadata, nil)
	}
	return nil
}

// ScoreCounts returns packet counts by deterministic classification. It is a
// cheap indexed aggregation used by the Traffic summary.
func (s *PacketStore) ScoreCounts() (map[string]int64, error) {
	rows, err := s.rdb.Query(`SELECT classification, COUNT(*) FROM packets
		WHERE classification <> '' GROUP BY classification`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var classification string
		var count int64
		if err := rows.Scan(&classification, &count); err != nil {
			return nil, err
		}
		out[classification] = count
	}
	return out, rows.Err()
}

// SetAnalystLabel annotates selected packets for later review. Labels never
// directly alter a score; an explicit "exploit" label is only consumed when
// the operator requests a deterministic baseline rebuild.
func (s *PacketStore) SetAnalystLabel(packetIDs []int64, label string) error {
	if len(packetIDs) == 0 {
		return nil
	}
	const chunkSize = 256
	for start := 0; start < len(packetIDs); start += chunkSize {
		end := start + chunkSize
		if end > len(packetIDs) {
			end = len(packetIDs)
		}
		marks := make([]string, end-start)
		args := make([]any, 0, 1+len(marks))
		args = append(args, label)
		for i, id := range packetIDs[start:end] {
			marks[i] = "?"
			args = append(args, id)
		}
		if _, err := s.db.Exec(`UPDATE packets SET analyst_label = ? WHERE id IN (`+strings.Join(marks, ",")+`)`, args...); err != nil {
			return fmt.Errorf("setting analyst label: %w", err)
		}
	}
	s.emitChange(PacketChangeMetadata, nil)
	return nil
}

// LoadBaselineSignatures restores the frozen opening-round baseline.
func (s *PacketStore) LoadBaselineSignatures() ([]BaselineSignature, error) {
	rows, err := s.rdb.Query(`SELECT service_id, signature, rounds FROM baseline_signatures`)
	if err != nil {
		return nil, fmt.Errorf("loading baseline signatures: %w", err)
	}
	defer rows.Close()
	var out []BaselineSignature
	for rows.Next() {
		var item BaselineSignature
		var roundsJSON string
		if err := rows.Scan(&item.ServiceID, &item.Signature, &roundsJSON); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(roundsJSON), &item.Rounds); err != nil {
			continue
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// CountBaselinePackets preflights the exact default and service-specific
// windows before the active baseline is cleared.
func (s *PacketStore) CountBaselinePackets(defaultWindow BaselineWindow, serviceWindows map[string]BaselineWindow) (int, error) {
	where, args := baselineSelection(defaultWindow, serviceWindows)
	if where == "" {
		return 0, nil
	}
	var total int
	if err := s.rdb.QueryRow("SELECT COUNT(*) FROM packets WHERE "+where, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("counting baseline replay: %w", err)
	}
	return total, nil
}

// ReplayBaselinePackets streams a bounded, chronological replay window in
// small batches. This avoids retaining thousands of captured bodies when the
// operator changes baseline rounds after traffic has already been captured.
func (s *PacketStore) ReplayBaselinePackets(defaultWindow BaselineWindow, serviceWindows map[string]BaselineWindow, limit int, visit func(*Packet) error) (int, error) {
	selection, selectionArgs := baselineSelection(defaultWindow, serviceWindows)
	if selection == "" {
		return 0, nil
	}
	if limit <= 0 || visit == nil {
		return 0, fmt.Errorf("baseline replay requires a positive limit and visitor")
	}
	const batchSize = 128
	total, err := s.CountBaselinePackets(defaultWindow, serviceWindows)
	if err != nil {
		return 0, err
	}
	if total > limit {
		return 0, fmt.Errorf("baseline window contains %d packets and exceeds the %d-packet safety limit; choose a narrower round range", total, limit)
	}
	count := 0
	var cursorTS string
	var cursorID int64
	for {
		fetch := batchSize
		if remaining := limit - count + 1; remaining < fetch {
			fetch = remaining
		}
		where := "(" + selection + ")"
		args := append(make([]interface{}, 0, len(selectionArgs)+4), selectionArgs...)
		if cursorTS != "" {
			where += " AND (timestamp > ? OR (timestamp = ? AND id > ?))"
			args = append(args, cursorTS, cursorTS, cursorID)
		}
		args = append(args, fetch)
		packets, err := s.scanPackets("SELECT "+packetSelectCols+" FROM packets WHERE "+where+" ORDER BY timestamp ASC, id ASC LIMIT ?", args)
		if err != nil {
			return count, fmt.Errorf("loading baseline replay: %w", err)
		}
		if len(packets) == 0 {
			return count, nil
		}
		for _, packet := range packets {
			if count >= limit {
				return count, fmt.Errorf("baseline window exceeds the %d-packet safety limit; choose a narrower round range", limit)
			}
			if err := visit(packet); err != nil {
				return count, err
			}
			count++
		}
		last := packets[len(packets)-1]
		cursorTS, cursorID = CanonicalTimestamp(last.Timestamp), last.ID
		if len(packets) < fetch {
			return count, nil
		}
	}
}

func baselineSelection(defaultWindow BaselineWindow, serviceWindows map[string]BaselineWindow) (string, []interface{}) {
	serviceIDs := make([]string, 0, len(serviceWindows))
	for serviceID, window := range serviceWindows {
		if serviceID != "" && validBaselineWindow(window) {
			serviceIDs = append(serviceIDs, serviceID)
		}
	}
	sort.Strings(serviceIDs)

	clauses := make([]string, 0, len(serviceIDs)+1)
	args := make([]interface{}, 0, 2+len(serviceIDs)*3)
	if validBaselineWindow(defaultWindow) {
		clause := "(timestamp >= ? AND timestamp < ?"
		args = append(args, CanonicalTimestamp(defaultWindow.From), CanonicalTimestamp(defaultWindow.To))
		if len(serviceIDs) > 0 {
			clause += " AND service_id NOT IN (" + strings.TrimSuffix(strings.Repeat("?,", len(serviceIDs)), ",") + ")"
			for _, serviceID := range serviceIDs {
				args = append(args, serviceID)
			}
		}
		clauses = append(clauses, clause+")")
	}
	for _, serviceID := range serviceIDs {
		window := serviceWindows[serviceID]
		clauses = append(clauses, "(service_id = ? AND timestamp >= ? AND timestamp < ?)")
		args = append(args, serviceID, CanonicalTimestamp(window.From), CanonicalTimestamp(window.To))
	}
	return strings.Join(clauses, " OR "), args
}

func validBaselineWindow(window BaselineWindow) bool {
	return !window.From.IsZero() && !window.To.IsZero() && window.To.After(window.From)
}

// PrepareBaseline activates a versioned snapshot. Switching configurations
// restores its signatures instead of deleting the previously active set.
func (s *PacketStore) PrepareBaseline(epoch, definition string) error {
	epoch = strings.TrimSpace(epoch)
	if epoch == "" {
		return fmt.Errorf("baseline epoch is empty")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var stored string
	err = tx.QueryRow(`SELECT value FROM baseline_meta WHERE key = 'epoch'`).Scan(&stored)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("reading baseline epoch: %w", err)
	}
	now := CanonicalTimestamp(time.Now())
	if _, err := tx.Exec(`INSERT INTO baseline_snapshot_meta(epoch, definition, created_at, updated_at)
		VALUES(?, ?, ?, ?)
		ON CONFLICT(epoch) DO UPDATE SET definition = excluded.definition`, epoch, definition, now, now); err != nil {
		return fmt.Errorf("saving baseline snapshot metadata: %w", err)
	}
	if err == sql.ErrNoRows || stored != epoch {
		if _, err := tx.Exec(`DELETE FROM baseline_signatures`); err != nil {
			return fmt.Errorf("switching baseline: %w", err)
		}
		if _, err := tx.Exec(`INSERT INTO baseline_signatures(service_id, signature, rounds)
			SELECT service_id, signature, rounds FROM baseline_snapshot_signatures WHERE epoch = ?`, epoch); err != nil {
			return fmt.Errorf("restoring baseline snapshot: %w", err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO baseline_meta(key, value) VALUES('epoch', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, epoch); err != nil {
		return fmt.Errorf("saving baseline epoch: %w", err)
	}
	return tx.Commit()
}

// UpsertBaselineSignature persists the observed opening rounds for a safe
// signature. Callers own anti-poisoning and freeze policy.
func (s *PacketStore) UpsertBaselineSignature(serviceID, signature string, rounds []int) error {
	encoded, err := json.Marshal(rounds)
	if err != nil {
		return fmt.Errorf("encoding baseline rounds: %w", err)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	epoch, err := activeBaselineEpoch(tx)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO baseline_signatures(service_id, signature, rounds) VALUES(?, ?, ?)
		ON CONFLICT(service_id, signature) DO UPDATE SET rounds = excluded.rounds`, serviceID, signature, string(encoded)); err != nil {
		return fmt.Errorf("saving baseline signature: %w", err)
	}
	if _, err = tx.Exec(`INSERT INTO baseline_snapshot_signatures(epoch, service_id, signature, rounds) VALUES(?, ?, ?, ?)
		ON CONFLICT(epoch, service_id, signature) DO UPDATE SET rounds = excluded.rounds`, epoch, serviceID, signature, string(encoded)); err != nil {
		return fmt.Errorf("saving versioned baseline signature: %w", err)
	}
	if err := touchBaselineSnapshot(tx, epoch); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteBaselineSignature removes a weak candidate evicted by the bounded
// in-memory baseline. Recurring candidates are never selected for eviction.
func (s *PacketStore) DeleteBaselineSignature(serviceID, signature string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	epoch, err := activeBaselineEpoch(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM baseline_signatures WHERE service_id = ? AND signature = ?`, serviceID, signature); err != nil {
		return fmt.Errorf("deleting baseline signature: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM baseline_snapshot_signatures WHERE epoch = ? AND service_id = ? AND signature = ?`, epoch, serviceID, signature); err != nil {
		return fmt.Errorf("deleting versioned baseline signature: %w", err)
	}
	if err := touchBaselineSnapshot(tx, epoch); err != nil {
		return err
	}
	return tx.Commit()
}

// ReplaceBaselineSignatures atomically publishes a completed historical
// rebuild. Live learning continues to use the cheaper single-row upsert.
func (s *PacketStore) ReplaceBaselineSignatures(items []BaselineSignature) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("starting baseline replacement: %w", err)
	}
	defer tx.Rollback()
	epoch, err := activeBaselineEpoch(tx)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM baseline_signatures`); err != nil {
		return fmt.Errorf("clearing baseline replacement: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM baseline_snapshot_signatures WHERE epoch = ?`, epoch); err != nil {
		return fmt.Errorf("clearing versioned baseline replacement: %w", err)
	}
	activeStmt, err := tx.Prepare(`INSERT INTO baseline_signatures(service_id, signature, rounds) VALUES(?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing baseline replacement: %w", err)
	}
	defer activeStmt.Close()
	snapshotStmt, err := tx.Prepare(`INSERT INTO baseline_snapshot_signatures(epoch, service_id, signature, rounds) VALUES(?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing versioned baseline replacement: %w", err)
	}
	defer snapshotStmt.Close()
	for _, item := range items {
		encoded, err := json.Marshal(item.Rounds)
		if err != nil {
			return fmt.Errorf("encoding baseline rounds: %w", err)
		}
		if _, err := activeStmt.Exec(item.ServiceID, item.Signature, string(encoded)); err != nil {
			return fmt.Errorf("replacing baseline signature: %w", err)
		}
		if _, err := snapshotStmt.Exec(epoch, item.ServiceID, item.Signature, string(encoded)); err != nil {
			return fmt.Errorf("replacing versioned baseline signature: %w", err)
		}
	}
	if err := touchBaselineSnapshot(tx, epoch); err != nil {
		return err
	}
	return tx.Commit()
}

// ListBaselineSnapshots returns every preserved configuration, including the
// active one. Packet cleanup never touches these tables.
func (s *PacketStore) ListBaselineSnapshots() ([]BaselineSnapshot, error) {
	rows, err := s.rdb.Query(`SELECT m.epoch, m.definition, m.created_at, m.updated_at,
		COUNT(s.signature), CASE WHEN m.epoch = COALESCE((SELECT value FROM baseline_meta WHERE key = 'epoch'), '') THEN 1 ELSE 0 END
		FROM baseline_snapshot_meta m
		LEFT JOIN baseline_snapshot_signatures s ON s.epoch = m.epoch
		GROUP BY m.epoch, m.definition, m.created_at, m.updated_at
		ORDER BY m.updated_at DESC, m.epoch ASC`)
	if err != nil {
		return nil, fmt.Errorf("listing baseline snapshots: %w", err)
	}
	defer rows.Close()
	var out []BaselineSnapshot
	for rows.Next() {
		var item BaselineSnapshot
		var createdAt, updatedAt string
		var active int
		if err := rows.Scan(&item.Epoch, &item.Definition, &createdAt, &updatedAt, &item.SignatureCount, &active); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		item.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)
		item.Active = active != 0
		out = append(out, item)
	}
	return out, rows.Err()
}

func activeBaselineEpoch(tx *sql.Tx) (string, error) {
	var epoch string
	if err := tx.QueryRow(`SELECT value FROM baseline_meta WHERE key = 'epoch'`).Scan(&epoch); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("active baseline is not prepared")
		}
		return "", fmt.Errorf("reading active baseline: %w", err)
	}
	return epoch, nil
}

func touchBaselineSnapshot(tx *sql.Tx, epoch string) error {
	if _, err := tx.Exec(`UPDATE baseline_snapshot_meta SET updated_at = ? WHERE epoch = ?`, CanonicalTimestamp(time.Now()), epoch); err != nil {
		return fmt.Errorf("updating baseline snapshot metadata: %w", err)
	}
	return nil
}

// Query retrieves packets matching the given filters.
// The regex filter and any DSL-residual predicates are applied in Go after
// the SQL query for correct pagination.
func (s *PacketStore) Query(q PacketQuery) ([]*Packet, int, error) {
	packets, total, _, err := s.QueryPage(q)
	return packets, total, err
}

// QueryPage is Query plus pagination metadata used by the UI to distinguish
// exact totals from bounded residual scans.
func (s *PacketStore) QueryPage(q PacketQuery) ([]*Packet, int, QueryMeta, error) {
	where, args, residual, err := buildWhereAndResidual(q)
	if err != nil {
		return nil, 0, QueryMeta{}, err
	}
	hasRegex := q.Regex != "" || q.NotRegex != ""
	hasResidual := residual != nil

	// Sort order
	sortOrder := "DESC"
	if q.SortOrder == "asc" {
		sortOrder = "ASC"
	}

	// Defaults
	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	selectCols := packetSelectCols
	useSummary := q.Summary && !hasRegex && !hasResidual
	if useSummary {
		selectCols = packetSummaryCols
	}

	if hasRegex || hasResidual {
		// Residual predicates are evaluated in bounded keyset chunks.
		return s.queryWithGoFilter(q, where, args, selectCols, sortOrder, limit, offset, residual)
	}

	// Fetch the page first, then only run COUNT(*) if it's cheap. COUNT on LIKE
	// predicates over body_string/headers is a full table scan and dominates
	// query time — in practice the UI only needs a bound ("is there another
	// page?") so we skip the expensive COUNT and estimate total.
	pageWhere, pageArgs := withPacketCursor(where, args, q.CursorTimestamp, q.CursorID, sortOrder)
	sqlOffset := offset
	if q.CursorTimestamp != "" {
		sqlOffset = 0
	}
	querySQL := "SELECT " + selectCols + " FROM packets" +
		pageWhere + " ORDER BY timestamp " + sortOrder + ", id " + sortOrder + " LIMIT ? OFFSET ?"
	queryArgs := append(pageArgs, limit+1, sqlOffset)

	var packets []*Packet
	if useSummary {
		packets, err = s.scanPacketsSummary(querySQL, queryArgs)
	} else {
		packets, err = s.scanPackets(querySQL, queryArgs)
	}
	if err != nil {
		return nil, 0, QueryMeta{}, err
	}
	more := len(packets) > limit
	if more {
		packets = packets[:limit]
	}

	total, err := s.countOrEstimate(q, where, args, offset, len(packets), more)
	if err != nil {
		return nil, 0, QueryMeta{}, err
	}
	meta := QueryMeta{TotalExact: !isExpensiveTextPredicate(q)}
	if more && len(packets) > 0 {
		last := packets[len(packets)-1]
		meta.NextTimestamp, meta.NextID = last.Timestamp, last.ID
	}
	return packets, total, meta, nil
}

func withPacketCursor(where string, args []interface{}, timestamp string, id int64, sortOrder string) (string, []interface{}) {
	out := append([]interface{}(nil), args...)
	if timestamp == "" || id <= 0 {
		return where, out
	}
	op := "<"
	if sortOrder == "ASC" {
		op = ">"
	}
	clause := fmt.Sprintf("(timestamp %s ? OR (timestamp = ? AND id %s ?))", op, op)
	if where == "" {
		where = " WHERE " + clause
	} else {
		where += " AND " + clause
	}
	out = append(out, timestamp, timestamp, id)
	return where, out
}

// countOrEstimate returns the exact COUNT(*) when the predicate is cheap, or an
// estimated total otherwise. "Cheap" = no wildcard LIKE / negation text scans.
// The estimate is tight enough for infinite-scroll (offset + returned ± 1).
func (s *PacketStore) countOrEstimate(q PacketQuery, where string, args []interface{}, offset, returned int, more bool) (int, error) {
	if isExpensiveTextPredicate(q) {
		// Estimate: the backend doesn't know the true total without a full scan.
		// Return offset+returned when the page isn't full (we've reached the end),
		// otherwise offset+returned+1 to signal "more available" to the client.
		if !more {
			return offset + returned, nil
		}
		return offset + returned + 1, nil
	}
	var total int
	countSQL := "SELECT COUNT(*) FROM packets" + where
	if err := s.rdb.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("counting packets: %w", err)
	}
	return total, nil
}

// isExpensiveTextPredicate returns true when the query uses a text-search
// predicate that forces a full table scan (wildcard LIKE on body/headers/url).
func isExpensiveTextPredicate(q PacketQuery) bool {
	return q.Contains != "" || q.NotContains != "" ||
		q.ContainsBody != "" || q.NotContainsBody != "" ||
		q.ContainsHeaders != "" || q.NotContainsHeaders != "" ||
		q.URL != "" || q.NotURL != "" || strings.TrimSpace(q.Q) != ""
}

// queryWithGoFilter fetches SQL-filtered rows, applies regex/not-regex and any
// DSL residual evaluator in Go, then paginates. Used whenever post-SQL
// filtering is required.
func (s *PacketStore) queryWithGoFilter(q PacketQuery, where string, args []interface{}, selectCols, sortOrder string, limit, offset int, residual filter.EvalFunc) ([]*Packet, int, QueryMeta, error) {
	var re, notRe *regexp.Regexp
	if q.Regex != "" {
		var err error
		re, err = regexp.Compile(q.Regex)
		if err != nil {
			return nil, 0, QueryMeta{}, fmt.Errorf("invalid regex: %w", err)
		}
	}
	if q.NotRegex != "" {
		var err error
		notRe, err = regexp.Compile(q.NotRegex)
		if err != nil {
			return nil, 0, QueryMeta{}, fmt.Errorf("invalid not_regex: %w", err)
		}
	}

	const chunkSize = 512
	const maxScan = 20000
	skip := offset
	if q.CursorTimestamp != "" {
		skip = 0
	}
	wanted := skip + limit + 1
	matched, scanned := 0, 0
	var selected []*Packet
	cursorTS := q.CursorTimestamp
	cursorID := q.CursorID
	var lastScanned *Packet
	exhausted := false
	for scanned < maxScan && matched < wanted {
		pageWhere := where
		pageArgs := append([]interface{}(nil), args...)
		if cursorTS != "" {
			op := "<"
			if sortOrder == "ASC" {
				op = ">"
			}
			cursorClause := fmt.Sprintf("(timestamp %s ? OR (timestamp = ? AND id %s ?))", op, op)
			if pageWhere == "" {
				pageWhere = " WHERE " + cursorClause
			} else {
				pageWhere += " AND " + cursorClause
			}
			pageArgs = append(pageArgs, cursorTS, cursorTS, cursorID)
		}
		remaining := maxScan - scanned
		fetch := chunkSize
		if remaining < fetch {
			fetch = remaining
		}
		querySQL := "SELECT " + selectCols + " FROM packets" + pageWhere + " ORDER BY timestamp " + sortOrder + ", id " + sortOrder + " LIMIT ?"
		pageArgs = append(pageArgs, fetch)
		page, err := s.scanPackets(querySQL, pageArgs)
		if err != nil {
			return nil, 0, QueryMeta{}, err
		}
		if len(page) == 0 {
			exhausted = true
			break
		}
		scanned += len(page)
		last := page[len(page)-1]
		lastScanned = last
		cursorTS, cursorID = CanonicalTimestamp(last.Timestamp), last.ID
		for _, p := range page {
			if re != nil && !regexMatchesPacket(re, p) {
				continue
			}
			if notRe != nil && regexMatchesPacket(notRe, p) {
				continue
			}
			if residual != nil && !residual(AsView(p)) {
				continue
			}
			if matched >= skip && len(selected) < limit+1 {
				selected = append(selected, p)
			}
			matched++
		}
		if len(page) < fetch {
			exhausted = true
			break
		}
	}
	more := len(selected) > limit
	if more {
		selected = selected[:limit]
	}
	total := matched
	if q.CursorTimestamp != "" {
		total += offset
	}
	if !exhausted {
		minimum := offset + len(selected)
		if more {
			minimum++
		}
		if total < minimum {
			total = minimum
		}
	}
	meta := QueryMeta{TotalExact: exhausted, Partial: !exhausted && !more}
	if more && len(selected) > 0 {
		last := selected[len(selected)-1]
		meta.NextTimestamp, meta.NextID = last.Timestamp, last.ID
	} else if !exhausted && lastScanned != nil {
		// The bounded scan may cross a long run with few/no residual matches.
		// Continue after the last row actually inspected so later matches remain
		// reachable without rescanning the same 20k rows.
		meta.NextTimestamp, meta.NextID = lastScanned.Timestamp, lastScanned.ID
	}
	return selected, total, meta, nil
}

func regexMatchesPacket(re *regexp.Regexp, p *Packet) bool {
	if p.BodyString != "" && re.MatchString(p.BodyString) {
		return true
	}
	if p.URL != "" && re.MatchString(p.URL) {
		return true
	}
	// Search in headers
	for k, v := range p.Headers {
		if re.MatchString(k + ": " + v) {
			return true
		}
	}
	return false
}

func (s *PacketStore) scanPackets(querySQL string, args []interface{}) ([]*Packet, error) {
	rows, err := s.rdb.Query(querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("querying packets: %w", err)
	}
	defer rows.Close()

	var packets []*Packet
	for rows.Next() {
		p := &Packet{}
		var ts string
		var headersJSON string
		var matchedRulesJSON string
		var matchedFlagIDsJSON string
		var verdictJSON string
		var decodedJSON string
		var scoreReasonsJSON string
		var flaggedInt, containsFlagIDInt, captureTruncatedInt int
		if err := rows.Scan(
			&p.ID, &p.ServiceID, &p.SessionID, &ts,
			&p.SrcIP, &p.SrcPort, &p.DstIP, &p.DstPort,
			&p.Protocol, &p.Direction,
			&p.Method, &p.URL, &p.Status,
			&headersJSON, &p.Body, &p.BodyString, &decodedJSON, &captureTruncatedInt,
			&matchedRulesJSON, &flaggedInt, &containsFlagIDInt,
			&p.FlagCountBody, &p.FlagCountHeaders, &p.FlagCountURL,
			&matchedFlagIDsJSON, &p.FlagIDRound, &verdictJSON, &p.AttackScore, &p.NormalScore, &p.ScoreCoverage, &p.ScoreConfidence, &p.Classification, &scoreReasonsJSON, &p.AnalystLabel,
		); err != nil {
			return nil, fmt.Errorf("scanning packet: %w", err)
		}

		p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		p.Flagged = flaggedInt != 0
		p.ContainsFlagID = containsFlagIDInt != 0
		p.CaptureTruncated = captureTruncatedInt != 0

		if headersJSON != "" && headersJSON != "{}" {
			json.Unmarshal([]byte(headersJSON), &p.Headers)
		}
		if decodedJSON != "" && decodedJSON != "{}" {
			json.Unmarshal([]byte(decodedJSON), &p.Decoded)
		}

		if matchedRulesJSON != "" && matchedRulesJSON != "[]" {
			json.Unmarshal([]byte(matchedRulesJSON), &p.MatchedRules)
		}

		if matchedFlagIDsJSON != "" && matchedFlagIDsJSON != "[]" {
			json.Unmarshal([]byte(matchedFlagIDsJSON), &p.MatchedFlagIDs)
		}
		if verdictJSON != "" && verdictJSON != "{}" {
			json.Unmarshal([]byte(verdictJSON), &p.Verdict)
		}
		if scoreReasonsJSON != "" && scoreReasonsJSON != "[]" {
			json.Unmarshal([]byte(scoreReasonsJSON), &p.ScoreReasons)
		}
		ensurePacketVerdict(p)

		if p.MatchedRules == nil {
			p.MatchedRules = []MatchedRuleInfo{}
		}
		if p.MatchedFlagIDs == nil {
			p.MatchedFlagIDs = []string{}
		}

		s.annotateRound(p)
		packets = append(packets, p)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// scanPacketsSummary scans rows produced by SELECTing packetSummaryCols.
// Returns Lite packets with body=nil, headers=nil, matched_flagids=[], and
// body_string truncated to a short preview. Clients should refetch by ID
// when the full body/headers are needed (UI does this on row click).
func (s *PacketStore) scanPacketsSummary(querySQL string, args []interface{}) ([]*Packet, error) {
	rows, err := s.rdb.Query(querySQL, args...)
	if err != nil {
		return nil, fmt.Errorf("querying packets: %w", err)
	}
	defer rows.Close()

	var packets []*Packet
	for rows.Next() {
		p := &Packet{Lite: true}
		var ts, bodyPreview, matchedRulesJSON, verdictJSON, scoreReasonsJSON string
		var flaggedInt, containsFlagIDInt, captureTruncatedInt int
		if err := rows.Scan(
			&p.ID, &p.ServiceID, &p.SessionID, &ts,
			&p.SrcIP, &p.SrcPort, &p.DstIP, &p.DstPort,
			&p.Protocol, &p.Direction,
			&p.Method, &p.URL, &p.Status,
			&bodyPreview, &captureTruncatedInt,
			&matchedRulesJSON, &flaggedInt, &containsFlagIDInt,
			&p.FlagCountBody, &p.FlagCountHeaders, &p.FlagCountURL,
			&p.FlagIDRound, &verdictJSON, &p.AttackScore, &p.NormalScore, &p.ScoreCoverage, &p.ScoreConfidence, &p.Classification, &scoreReasonsJSON, &p.AnalystLabel,
		); err != nil {
			return nil, fmt.Errorf("scanning packet summary: %w", err)
		}

		p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		p.Flagged = flaggedInt != 0
		p.ContainsFlagID = containsFlagIDInt != 0
		p.CaptureTruncated = captureTruncatedInt != 0
		p.BodyString = bodyPreview

		if matchedRulesJSON != "" && matchedRulesJSON != "[]" {
			json.Unmarshal([]byte(matchedRulesJSON), &p.MatchedRules)
		}
		if p.MatchedRules == nil {
			p.MatchedRules = []MatchedRuleInfo{}
		}
		if verdictJSON != "" && verdictJSON != "{}" {
			json.Unmarshal([]byte(verdictJSON), &p.Verdict)
		}
		ensurePacketVerdict(p)
		if scoreReasonsJSON != "" && scoreReasonsJSON != "[]" {
			json.Unmarshal([]byte(scoreReasonsJSON), &p.ScoreReasons)
		}
		p.MatchedFlagIDs = []string{}

		s.annotateRound(p)
		packets = append(packets, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// GetPacketByID returns a single packet by its ID.
func (s *PacketStore) GetPacketByID(id int64) (*Packet, error) {
	selectCols := packetSelectCols
	row := s.rdb.QueryRow("SELECT "+selectCols+" FROM packets WHERE id = ?", id)

	p := &Packet{}
	var ts string
	var headersJSON string
	var matchedRulesJSON string
	var matchedFlagIDsJSON string
	var verdictJSON string
	var decodedJSON string
	var scoreReasonsJSON string
	var flaggedInt, containsFlagIDInt, captureTruncatedInt int
	if err := row.Scan(
		&p.ID, &p.ServiceID, &p.SessionID, &ts,
		&p.SrcIP, &p.SrcPort, &p.DstIP, &p.DstPort,
		&p.Protocol, &p.Direction,
		&p.Method, &p.URL, &p.Status,
		&headersJSON, &p.Body, &p.BodyString, &decodedJSON, &captureTruncatedInt,
		&matchedRulesJSON, &flaggedInt, &containsFlagIDInt,
		&p.FlagCountBody, &p.FlagCountHeaders, &p.FlagCountURL,
		&matchedFlagIDsJSON, &p.FlagIDRound, &verdictJSON, &p.AttackScore, &p.NormalScore, &p.ScoreCoverage, &p.ScoreConfidence, &p.Classification, &scoreReasonsJSON, &p.AnalystLabel,
	); err != nil {
		return nil, err
	}

	p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	p.Flagged = flaggedInt != 0
	p.ContainsFlagID = containsFlagIDInt != 0
	p.CaptureTruncated = captureTruncatedInt != 0

	if headersJSON != "" && headersJSON != "{}" {
		json.Unmarshal([]byte(headersJSON), &p.Headers)
	}
	if decodedJSON != "" && decodedJSON != "{}" {
		json.Unmarshal([]byte(decodedJSON), &p.Decoded)
	}
	if matchedRulesJSON != "" && matchedRulesJSON != "[]" {
		json.Unmarshal([]byte(matchedRulesJSON), &p.MatchedRules)
	}
	if matchedFlagIDsJSON != "" && matchedFlagIDsJSON != "[]" {
		json.Unmarshal([]byte(matchedFlagIDsJSON), &p.MatchedFlagIDs)
	}
	if verdictJSON != "" && verdictJSON != "{}" {
		json.Unmarshal([]byte(verdictJSON), &p.Verdict)
	}
	if scoreReasonsJSON != "" && scoreReasonsJSON != "[]" {
		json.Unmarshal([]byte(scoreReasonsJSON), &p.ScoreReasons)
	}
	ensurePacketVerdict(p)
	if p.MatchedRules == nil {
		p.MatchedRules = []MatchedRuleInfo{}
	}
	if p.MatchedFlagIDs == nil {
		p.MatchedFlagIDs = []string{}
	}
	s.annotateRound(p)

	return p, nil
}

// InsertAlert stores an alert in the database.
func (s *PacketStore) InsertAlert(a *Alert) error {
	res, err := s.db.Exec(`
		INSERT INTO alerts (packet_id, rule_id, service_id, src_ip, timestamp, pattern_matched)
		VALUES (?, ?, ?, ?, ?, ?)`,
		a.PacketID, a.RuleID, a.ServiceID, a.SrcIP,
		CanonicalTimestamp(a.Timestamp),
		a.PatternMatched,
	)
	if err != nil {
		return fmt.Errorf("inserting alert: %w", err)
	}
	id, _ := res.LastInsertId()
	a.ID = id
	return nil
}

// QueryAlerts retrieves alerts matching the given filters.
func (s *PacketStore) QueryAlerts(q AlertQuery) ([]*Alert, int, error) {
	var conditions []string
	var args []interface{}

	if q.ServiceID != "" {
		conditions = append(conditions, "a.service_id = ?")
		args = append(args, q.ServiceID)
	}
	if q.RuleID != "" {
		conditions = append(conditions, "a.rule_id = ?")
		args = append(args, q.RuleID)
	}
	if q.SrcIP != "" {
		conditions = append(conditions, "a.src_ip = ?")
		args = append(args, q.SrcIP)
	}
	if q.NotServiceID != "" {
		conditions = append(conditions, "a.service_id != ?")
		args = append(args, q.NotServiceID)
	}
	if q.NotRuleID != "" {
		conditions = append(conditions, "a.rule_id != ?")
		args = append(args, q.NotRuleID)
	}
	if q.NotSrcIP != "" {
		conditions = append(conditions, "a.src_ip != ?")
		args = append(args, q.NotSrcIP)
	}
	if q.TimeFrom != nil {
		conditions = append(conditions, "a.timestamp >= ?")
		args = append(args, CanonicalTimestamp(*q.TimeFrom))
	}
	if q.TimeTo != nil {
		conditions = append(conditions, "a.timestamp <= ?")
		args = append(args, CanonicalTimestamp(*q.TimeTo))
	}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count
	var total int
	countSQL := "SELECT COUNT(*) FROM alerts a" + where
	if err := s.rdb.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting alerts: %w", err)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}

	querySQL := "SELECT a.id, a.packet_id, a.rule_id, a.service_id, a.src_ip, a.timestamp, a.pattern_matched FROM alerts a" +
		where + " ORDER BY a.timestamp DESC, a.id DESC LIMIT ? OFFSET ?"
	queryArgs := append(args, limit, offset)

	rows, err := s.rdb.Query(querySQL, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*Alert
	for rows.Next() {
		a := &Alert{}
		var ts string
		if err := rows.Scan(&a.ID, &a.PacketID, &a.RuleID, &a.ServiceID, &a.SrcIP, &ts, &a.PatternMatched); err != nil {
			return nil, 0, fmt.Errorf("scanning alert: %w", err)
		}
		a.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		alerts = append(alerts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return alerts, total, nil
}

// GetAlert returns a single alert by ID.
func (s *PacketStore) GetAlert(id int64) (*Alert, error) {
	a := &Alert{}
	var ts string
	err := s.rdb.QueryRow(
		"SELECT id, packet_id, rule_id, service_id, src_ip, timestamp, pattern_matched FROM alerts WHERE id = ?", id,
	).Scan(&a.ID, &a.PacketID, &a.RuleID, &a.ServiceID, &a.SrcIP, &ts, &a.PatternMatched)
	if err != nil {
		return nil, err
	}
	a.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	return a, nil
}

// ClearAlerts deletes all alerts.
func (s *PacketStore) ClearAlerts() error {
	_, err := s.db.Exec("DELETE FROM alerts")
	return err
}

// ---- Saved flows ----

// InsertSavedFlow persists a new saved flow along with a JSON snapshot of each
// packet's full data, so the flow stays inspectable even after the packets
// table is purged. PacketIDs is derived from the supplied packets.
func (s *PacketStore) InsertSavedFlow(sf *SavedFlow, packets []*Packet) error {
	if sf.PacketIDs == nil && packets != nil {
		sf.PacketIDs = make([]int64, len(packets))
		for i, p := range packets {
			sf.PacketIDs[i] = p.ID
		}
	}
	idsJSON, err := json.Marshal(sf.PacketIDs)
	if err != nil {
		return fmt.Errorf("marshalling packet_ids: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("beginning saved flow tx: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		`INSERT INTO saved_flows (name, anchor_packet_id, packet_ids, created_by, created_at, notes)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		sf.Name, sf.AnchorPacketID, string(idsJSON), sf.CreatedBy,
		CanonicalTimestamp(sf.CreatedAt), sf.Notes,
	)
	if err != nil {
		return fmt.Errorf("inserting saved flow: %w", err)
	}
	sf.ID, _ = res.LastInsertId()

	for i, p := range packets {
		if p == nil {
			continue
		}
		blob, jerr := json.Marshal(p)
		if jerr != nil {
			return fmt.Errorf("marshalling snapshot packet: %w", jerr)
		}
		if _, err := tx.Exec(
			`INSERT INTO saved_flow_packets (saved_flow_id, ordinal, packet_id, data)
			 VALUES (?, ?, ?, ?)`,
			sf.ID, i, p.ID, blob,
		); err != nil {
			return fmt.Errorf("inserting saved flow snapshot: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing saved flow: %w", err)
	}
	return nil
}

// GetPacketByIDFromSnapshots returns a single packet by ID by searching the
// saved-flow snapshot table. Used as a fallback when the live `packets` row
// has been purged but the packet is still available through a saved flow —
// without this the decode endpoints (gRPC / custom protocol) couldn't render
// inside the Saved Flows page once live packets get cleaned up.
func (s *PacketStore) GetPacketByIDFromSnapshots(id int64) (*Packet, error) {
	row := s.rdb.QueryRow(
		`SELECT data FROM saved_flow_packets WHERE packet_id = ? LIMIT 1`,
		id,
	)
	var blob []byte
	if err := row.Scan(&blob); err != nil {
		return nil, err
	}
	p := &Packet{}
	if err := json.Unmarshal(blob, p); err != nil {
		return nil, fmt.Errorf("decoding saved flow snapshot: %w", err)
	}
	return p, nil
}

// GetSavedFlowSnapshot returns the snapshotted packets for a saved flow,
// ordered as they were captured. Returns an empty slice if no snapshot exists
// (legacy flows pinned before snapshots were introduced).
func (s *PacketStore) GetSavedFlowSnapshot(flowID int64) ([]*Packet, error) {
	rows, err := s.rdb.Query(
		`SELECT data FROM saved_flow_packets WHERE saved_flow_id = ? ORDER BY ordinal ASC`,
		flowID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying saved flow snapshot: %w", err)
	}
	defer rows.Close()

	var packets []*Packet
	for rows.Next() {
		var blob []byte
		if err := rows.Scan(&blob); err != nil {
			return nil, fmt.Errorf("scanning saved flow snapshot: %w", err)
		}
		p := &Packet{}
		if err := json.Unmarshal(blob, p); err != nil {
			return nil, fmt.Errorf("decoding saved flow snapshot: %w", err)
		}
		packets = append(packets, p)
	}
	return packets, rows.Err()
}

// ListSavedFlows returns all saved flows ordered newest-first.
func (s *PacketStore) ListSavedFlows() ([]*SavedFlow, error) {
	rows, err := s.rdb.Query(
		`SELECT id, name, anchor_packet_id, packet_ids, created_by, created_at, notes
		 FROM saved_flows ORDER BY id DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var flows []*SavedFlow
	for rows.Next() {
		sf, err := scanSavedFlow(rows)
		if err != nil {
			return nil, err
		}
		flows = append(flows, sf)
	}
	return flows, rows.Err()
}

// GetSavedFlowByID returns a single saved flow.
func (s *PacketStore) GetSavedFlowByID(id int64) (*SavedFlow, error) {
	row := s.rdb.QueryRow(
		`SELECT id, name, anchor_packet_id, packet_ids, created_by, created_at, notes
		 FROM saved_flows WHERE id = ?`, id,
	)
	return scanSavedFlow(row)
}

// DeleteSavedFlow removes a saved flow by ID along with its snapshotted packets.
func (s *PacketStore) DeleteSavedFlow(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM saved_flow_packets WHERE saved_flow_id = ?", id); err != nil {
		return fmt.Errorf("deleting saved flow snapshots: %w", err)
	}
	res, err := tx.Exec("DELETE FROM saved_flows WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("deleting saved flow: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking saved flow deletion: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("saved flow not found")
	}
	return tx.Commit()
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanSavedFlow(row rowScanner) (*SavedFlow, error) {
	sf := &SavedFlow{}
	var idsJSON, ts string
	if err := row.Scan(&sf.ID, &sf.Name, &sf.AnchorPacketID, &idsJSON, &sf.CreatedBy, &ts, &sf.Notes); err != nil {
		return nil, err
	}
	sf.CreatedAt, _ = time.Parse(time.RFC3339Nano, ts)
	if err := json.Unmarshal([]byte(idsJSON), &sf.PacketIDs); err != nil {
		sf.PacketIDs = []int64{}
	}
	return sf, nil
}

// PurgeAll deletes all packets and alerts from the database.
// Returns the number of rows deleted from each table.
func (s *PacketStore) PurgeAll() (packetsDeleted, alertsDeleted int64, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec("DELETE FROM alerts")
	if err != nil {
		return 0, 0, fmt.Errorf("deleting all alerts: %w", err)
	}
	alertsDeleted, _ = res.RowsAffected()

	res, err = tx.Exec("DELETE FROM packets")
	if err != nil {
		return 0, 0, fmt.Errorf("deleting all packets: %w", err)
	}
	packetsDeleted, _ = res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	s.CheckpointWAL()
	return packetsDeleted, alertsDeleted, nil
}

// PurgePackets deletes all packets (and their associated alerts) but preserves
// standalone alert configuration. Returns the number of packets deleted.
func (s *PacketStore) PurgePackets() (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM alerts"); err != nil {
		return 0, fmt.Errorf("deleting packet alerts: %w", err)
	}
	res, err := tx.Exec("DELETE FROM packets")
	if err != nil {
		return 0, fmt.Errorf("deleting all packets: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.CheckpointWAL()
	return n, nil
}

// DeletePacketIDs deletes the specified packets and their linked alerts.
// Returns the number of packets actually deleted.
func (s *PacketStore) DeletePacketIDs(ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var n int64
	for start := 0; start < len(ids); start += 500 {
		end := start + 500
		if end > len(ids) {
			end = len(ids)
		}
		chunk := ids[start:end]
		marks := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		if _, err := tx.Exec("DELETE FROM alerts WHERE packet_id IN ("+marks+")", args...); err != nil {
			return 0, fmt.Errorf("deleting packet alerts by ID: %w", err)
		}
		res, err := tx.Exec("DELETE FROM packets WHERE id IN ("+marks+")", args...)
		if err != nil {
			return 0, fmt.Errorf("deleting packets by ID: %w", err)
		}
		deleted, _ := res.RowsAffected()
		n += deleted
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	if n > 0 {
		s.emitChange(PacketChangeMetadata, nil)
	}
	return n, nil
}

// PurgeDroppedPackets deletes all packets that were dropped by a rule (has_drop_match=1)
// and their associated alerts. Returns the number of packets deleted.
func (s *PacketStore) PurgeDroppedPackets() (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM alerts WHERE packet_id IN (SELECT id FROM packets WHERE has_drop_match = 1)"); err != nil {
		return 0, fmt.Errorf("deleting dropped packet alerts: %w", err)
	}
	res, err := tx.Exec("DELETE FROM packets WHERE has_drop_match = 1")
	if err != nil {
		return 0, fmt.Errorf("deleting dropped packets: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// DeleteOlderThan deletes packets (and their alerts) whose *insertion time*
// is older than the given cutoff. Cleanup uses inserted_at — not the wire
// timestamp — so importing an old PCAP doesn't immediately make every row
// eligible for deletion just because the capture clock is in the past.
func (s *PacketStore) DeleteOlderThan(before time.Time) (packetsDeleted, alertsDeleted int64, err error) {
	ts := CanonicalTimestamp(before)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec("DELETE FROM alerts WHERE packet_id IN (SELECT id FROM packets WHERE inserted_at < ?)", ts)
	if err != nil {
		return 0, 0, fmt.Errorf("deleting old alerts: %w", err)
	}
	alertsDeleted, _ = res.RowsAffected()

	res, err = tx.Exec("DELETE FROM packets WHERE inserted_at < ?", ts)
	if err != nil {
		return 0, 0, fmt.Errorf("deleting old packets: %w", err)
	}
	packetsDeleted, _ = res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return packetsDeleted, alertsDeleted, nil
}

// DeleteOlderThanBatch removes at most limit old packets. Automatic cleanup
// deliberately uses small transactions so the proxy writer can acquire the
// single SQLite write connection between batches.
func (s *PacketStore) DeleteOlderThanBatch(before time.Time, limit int) (packetsDeleted, alertsDeleted int64, err error) {
	if limit <= 0 {
		return 0, 0, nil
	}
	ts := CanonicalTimestamp(before)
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM alerts WHERE packet_id IN (
		SELECT id FROM packets WHERE inserted_at < ? ORDER BY inserted_at ASC LIMIT ?
	)`, ts, limit)
	if err != nil {
		return 0, 0, fmt.Errorf("batch deleting old alerts: %w", err)
	}
	alertsDeleted, _ = res.RowsAffected()
	res, err = tx.Exec(`DELETE FROM packets WHERE id IN (
		SELECT id FROM packets WHERE inserted_at < ? ORDER BY inserted_at ASC LIMIT ?
	)`, ts, limit)
	if err != nil {
		return 0, 0, fmt.Errorf("batch deleting old packets: %w", err)
	}
	packetsDeleted, _ = res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return packetsDeleted, alertsDeleted, nil
}

// DeleteOldestBatch removes at most limit packets, ordered by insertion time.
// It is the primitive used by size-based automatic cleanup.
func (s *PacketStore) DeleteOldestBatch(limit int) (packetsDeleted, alertsDeleted int64, err error) {
	if limit <= 0 {
		return 0, 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM alerts WHERE packet_id IN (
		SELECT id FROM packets ORDER BY inserted_at ASC LIMIT ?
	)`, limit)
	if err != nil {
		return 0, 0, fmt.Errorf("batch deleting alerts: %w", err)
	}
	alertsDeleted, _ = res.RowsAffected()
	res, err = tx.Exec(`DELETE FROM packets WHERE id IN (
		SELECT id FROM packets ORDER BY inserted_at ASC LIMIT ?
	)`, limit)
	if err != nil {
		return 0, 0, fmt.Errorf("batch deleting packets: %w", err)
	}
	packetsDeleted, _ = res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	return packetsDeleted, alertsDeleted, nil
}

// DeleteOldestUntilSize deletes the oldest packets (and their alerts) until the DB is below maxSizeBytes.
// Returns the number of rows deleted from each table.
func (s *PacketStore) DeleteOldestUntilSize(maxSizeBytes int64) (packetsDeleted, alertsDeleted int64, err error) {
	for {
		size, sizeErr := s.DBUsedSize()
		if sizeErr != nil {
			return packetsDeleted, alertsDeleted, sizeErr
		}
		if size <= maxSizeBytes {
			return packetsDeleted, alertsDeleted, nil
		}

		pd, ad, execErr := s.DeleteOldestBatch(1000)
		if execErr != nil {
			return packetsDeleted, alertsDeleted, execErr
		}
		alertsDeleted += ad
		packetsDeleted += pd

		if pd == 0 {
			return packetsDeleted, alertsDeleted, nil
		}
	}
}

// SmartBackfillFlagIDs re-scans packets that were tagged with an older AC automaton
// (flagid_round < currentRound) within a recent time window. Uses the Aho-Corasick
// matcher for O(text_length) scanning instead of LIKE queries. Called automatically
// after each poller fetch.
func (s *PacketStore) SmartBackfillFlagIDs(checker FlagIDChecker, currentRound int) (int64, error) {
	if checker == nil || currentRound == 0 {
		return 0, nil
	}
	// The poller publishes the new matcher before invoking this callback. A
	// queue marker therefore separates packets scanned with the previous matcher
	// from newly accepted packets, and guarantees the former are queryable below.
	if err := s.Flush(context.Background()); err != nil {
		return 0, fmt.Errorf("flushing packet writer before smart backfill: %w", err)
	}

	// Only backfill packets from the last 60 seconds (the limbo between round start
	// and flagId fetch completion). Older packets were already scanned with the
	// automaton that was current at their insertion time.
	cutoff := CanonicalTimestamp(time.Now().Add(-60 * time.Second))

	var total int64
	const batchSize = 500
	const updateChunk = 32
	cursorTS := cutoff
	var cursorID int64

	for {
		// Scan through the read-only pool so decoding large bodies never occupies
		// the sole writer connection. Timestamp keyset pagination limits each
		// round-change backfill to the recent limbo window instead of walking the
		// historical table in row-id order.
		rows, err := s.rdb.Query(
			`SELECT id, timestamp, body, body_string, url, headers
			 FROM packets
			 WHERE flagid_scanned_round < ? AND timestamp >= ?
			   AND (timestamp > ? OR (timestamp = ? AND id > ?))
			 ORDER BY timestamp ASC, id ASC LIMIT ?`,
			currentRound, cutoff, cursorTS, cursorTS, cursorID, batchSize,
		)
		if err != nil {
			return total, fmt.Errorf("smart backfill select: %w", err)
		}

		type pktUpdate struct {
			id      int64
			matched []string
			round   int
		}
		var updates []pktUpdate
		var markProcessed []int64 // packets with no match, just update flagid_round

		for rows.Next() {
			var id int64
			var timestamp string
			var body []byte
			var bodyStr, url, headers string
			if err := rows.Scan(&id, &timestamp, &body, &bodyStr, &url, &headers); err != nil {
				rows.Close()
				return total, fmt.Errorf("smart backfill scan: %w", err)
			}
			cursorTS, cursorID = timestamp, id
			text := url + " " + headers + " " + bodyStr
			if bodyStr == "" && len(body) > 0 {
				text += " " + string(body)
			}
			matches := checker.FindMatchingFlagIDs(text)
			if len(matches) > 0 {
				vals := make([]string, len(matches))
				for i, m := range matches {
					vals[i] = m.FlagID
				}
				updates = append(updates, pktUpdate{id: id, matched: vals, round: roundFromFlagIDMatches(matches, currentRound)})
			} else {
				markProcessed = append(markProcessed, id)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return total, fmt.Errorf("smart backfill rows: %w", err)
		}
		rows.Close()

		batchCount := len(updates) + len(markProcessed)
		if batchCount == 0 {
			break // no more packets to process
		}

		// Apply updates in chunked transactions
		allOps := make([]pktUpdate, 0, batchCount)
		for _, u := range updates {
			allOps = append(allOps, u)
		}
		for _, id := range markProcessed {
			allOps = append(allOps, pktUpdate{id: id, matched: nil, round: currentRound})
		}

		for chunkStart := 0; chunkStart < len(allOps); chunkStart += updateChunk {
			chunkEnd := chunkStart + updateChunk
			if chunkEnd > len(allOps) {
				chunkEnd = len(allOps)
			}
			tx, err := s.db.Begin()
			if err != nil {
				return total, fmt.Errorf("smart backfill begin tx: %w", err)
			}
			matchedInChunk := int64(0)
			for _, op := range allOps[chunkStart:chunkEnd] {
				if op.matched != nil {
					mjson, _ := json.Marshal(op.matched)
					_, err = tx.Exec(
						"UPDATE packets SET contains_flagid = 1, matched_flagids = ?, flagid_round = ?, flagid_scanned_round = ? WHERE id = ?",
						string(mjson), op.round, currentRound, op.id,
					)
					matchedInChunk++
				} else {
					_, err = tx.Exec(
						"UPDATE packets SET flagid_round = ?, flagid_scanned_round = ? WHERE id = ?",
						op.round, currentRound, op.id,
					)
				}
				if err != nil {
					tx.Rollback()
					return total, fmt.Errorf("smart backfill update: %w", err)
				}
			}
			if err := tx.Commit(); err != nil {
				return total, fmt.Errorf("smart backfill commit: %w", err)
			}
			total += matchedInChunk
		}

		if batchCount < batchSize {
			break // last batch
		}
	}

	if total > 0 {
		s.emitChange(PacketChangeMetadata, nil)
	}
	return total, nil
}

// BackfillFlagIDsWindow applies flag-ID matching to packets captured in [from, to].
// Used by static mode to avoid periodic backfills.
func (s *PacketStore) BackfillFlagIDsWindow(checker FlagIDChecker, currentRound int, from, to time.Time) (int64, error) {
	return s.BackfillFlagIDsWindowForServices(checker, currentRound, from, to, nil)
}

// BackfillFlagIDsWindowForServices applies flag-ID matching to packets captured
// in [from, to] for the requested services. An empty serviceIDs slice preserves
// the legacy behavior and scans every service in the window.
func (s *PacketStore) BackfillFlagIDsWindowForServices(checker FlagIDChecker, currentRound int, from, to time.Time, serviceIDs []string) (int64, error) {
	if checker == nil || currentRound == 0 {
		return 0, nil
	}
	if err := s.Flush(context.Background()); err != nil {
		return 0, fmt.Errorf("flushing packet writer before window backfill: %w", err)
	}
	fromTS := CanonicalTimestamp(from)
	toTS := CanonicalTimestamp(to)

	var total int64
	const batchSize = 500
	const updateChunk = 32

	var lastID int64
	for {
		query := `SELECT id, body, body_string, url, headers
			 FROM packets
			 WHERE id > ? AND timestamp >= ? AND timestamp <= ?`
		args := make([]interface{}, 0, len(serviceIDs)+4)
		args = append(args, lastID, fromTS, toTS)
		if len(serviceIDs) > 0 {
			placeholders := make([]string, len(serviceIDs))
			for i, serviceID := range serviceIDs {
				placeholders[i] = "?"
				args = append(args, serviceID)
			}
			query += " AND service_id IN (" + strings.Join(placeholders, ",") + ")"
		}
		query += " ORDER BY id ASC LIMIT ?"
		args = append(args, batchSize)

		rows, err := s.rdb.Query(query, args...)
		if err != nil {
			return total, fmt.Errorf("window backfill select: %w", err)
		}

		type pktUpdate struct {
			id      int64
			matched []string
			round   int
		}
		var updates []pktUpdate
		var markProcessed []int64

		for rows.Next() {
			var id int64
			var body []byte
			var bodyStr, url, headers string
			if err := rows.Scan(&id, &body, &bodyStr, &url, &headers); err != nil {
				rows.Close()
				return total, fmt.Errorf("window backfill scan: %w", err)
			}
			lastID = id
			if bodyStr == "" && len(body) > 0 {
				bodyStr = string(body)
			}
			text := url + " " + headers + " " + bodyStr
			matches := checker.FindMatchingFlagIDs(text)
			if len(matches) > 0 {
				vals := make([]string, len(matches))
				for i, m := range matches {
					vals[i] = m.FlagID
				}
				updates = append(updates, pktUpdate{id: id, matched: vals, round: roundFromFlagIDMatches(matches, currentRound)})
			} else {
				markProcessed = append(markProcessed, id)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return total, fmt.Errorf("window backfill rows: %w", err)
		}
		rows.Close()

		batchCount := len(updates) + len(markProcessed)
		if batchCount == 0 {
			break
		}

		allOps := make([]pktUpdate, 0, batchCount)
		allOps = append(allOps, updates...)
		for _, id := range markProcessed {
			allOps = append(allOps, pktUpdate{id: id, round: currentRound})
		}

		for chunkStart := 0; chunkStart < len(allOps); chunkStart += updateChunk {
			chunkEnd := chunkStart + updateChunk
			if chunkEnd > len(allOps) {
				chunkEnd = len(allOps)
			}
			tx, err := s.db.Begin()
			if err != nil {
				return total, fmt.Errorf("window backfill begin tx: %w", err)
			}
			matchedInChunk := int64(0)
			for _, op := range allOps[chunkStart:chunkEnd] {
				if op.matched != nil {
					mjson, _ := json.Marshal(op.matched)
					_, err = tx.Exec(
						"UPDATE packets SET contains_flagid = 1, matched_flagids = ?, flagid_round = ?, flagid_scanned_round = ? WHERE id = ?",
						string(mjson), op.round, currentRound, op.id,
					)
					matchedInChunk++
				} else {
					_, err = tx.Exec(
						"UPDATE packets SET flagid_round = ?, flagid_scanned_round = ? WHERE id = ?",
						op.round, currentRound, op.id,
					)
				}
				if err != nil {
					tx.Rollback()
					return total, fmt.Errorf("window backfill update: %w", err)
				}
			}
			if err := tx.Commit(); err != nil {
				return total, fmt.Errorf("window backfill commit: %w", err)
			}
			total += matchedInChunk
		}

		if batchCount < batchSize {
			break
		}
	}

	if total > 0 {
		s.emitChange(PacketChangeMetadata, nil)
	}
	return total, nil
}

// DBSize returns the total on-disk size of the database (main + WAL + SHM).
func (s *PacketStore) DBSize() (int64, error) {
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if info, err := os.Stat(s.dbPath + suffix); err == nil {
			total += info.Size()
		}
	}
	return total, nil
}

// DBUsedSize reports logical SQLite bytes currently in use. Physical files do
// not shrink after DELETE and the WAL may temporarily grow, so using DBSize as
// an automatic-cleanup stop condition can otherwise delete every packet while
// waiting for a VACUUM/checkpoint that never happens.
func (s *PacketStore) DBUsedSize() (int64, error) {
	var pageCount, freePages, pageSize int64
	if err := s.db.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow("PRAGMA freelist_count").Scan(&freePages); err != nil {
		return 0, err
	}
	if err := s.db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
		return 0, err
	}
	usedPages := pageCount - freePages
	if usedPages < 0 {
		usedPages = 0
	}
	return usedPages * pageSize, nil
}

// CheckpointWAL asks SQLite to recycle completed WAL pages without waiting for
// active readers. It is safe for background cleanup and avoids VACUUM stalls.
func (s *PacketStore) CheckpointWAL() {
	_, _ = s.db.Exec("PRAGMA wal_checkpoint(PASSIVE)")
}

// NotifyMetadataChange refreshes live clients once after a group of cleanup
// batches, instead of once per DELETE.
func (s *PacketStore) NotifyMetadataChange() {
	s.emitChange(PacketChangeMetadata, nil)
}

// Drain stops the batched writer and waits until every packet accepted before
// the stop has been flushed. The database remains available to downstream
// scoring/filter workers during an orderly shutdown.
func (s *PacketStore) Drain() {
	s.lifecycleMu.Lock()
	s.writerStopped = true
	s.lifecycleMu.Unlock()
	s.stopOnce.Do(func() { close(s.stopCh) })
	<-s.doneCh
}

// Close is concurrent-safe and idempotent.
func (s *PacketStore) Close() error {
	s.closeOnce.Do(func() {
		s.Drain()
		s.closeErr = errors.Join(s.rdb.Close(), s.db.Close())
	})
	return s.closeErr
}

// QueryFlow finds all packets in the same logical flow as the given packet.
// It first tries auth token correlation (Bearer, Cookie, JSON "token" fields)
// across TCP connections. If no tokens are found, it falls back to peer IP
// correlation within a time window — grouping all connections from the same
// attacker IP to the same service.
func (s *PacketStore) QueryFlow(packetID int64) ([]*Packet, error) {
	// Step 1: get the starting packet
	startPkt, err := s.GetPacketByID(packetID)
	if err != nil {
		return nil, fmt.Errorf("packet %d not found: %w", packetID, err)
	}

	// Step 2: get all packets in the same service/session. Legacy or imported
	// rows may have an empty session ID; querying "session_id = ''" would join
	// every such packet in the database into one unrelated flow.
	sessionPackets := []*Packet{startPkt}
	if startPkt.SessionID != "" {
		sessionPackets, err = s.scanPackets(
			"SELECT "+packetSelectCols+" FROM packets WHERE service_id = ? AND session_id = ? ORDER BY timestamp ASC, id ASC",
			[]interface{}{startPkt.ServiceID, startPkt.SessionID},
		)
		if err != nil {
			return nil, err
		}
	} else {
		// An empty legacy/import session is not a correlation key. Even a token
		// match cannot safely fetch session_id='' because that would include every
		// unrelated legacy packet carrying the same missing value.
		return sessionPackets, nil
	}

	// Step 3: extract auth tokens from all packets in this session
	tokens := extractAuthTokens(sessionPackets)
	if len(tokens) == 0 {
		// No tokens — fallback to peer IP correlation within a time window.
		// This handles stateless HTTP exploits that don't use auth tokens.
		return s.flowByPeerIP(startPkt, sessionPackets)
	}

	// Correlation window around the current session to reduce false positives
	w := s.flowCorrelationWindow()
	minTime := sessionPackets[0].Timestamp.Add(-w)
	maxTime := sessionPackets[len(sessionPackets)-1].Timestamp.Add(w)
	minTS := CanonicalTimestamp(minTime)
	maxTS := CanonicalTimestamp(maxTime)

	// In non-SNAT environments, constrain token correlation to the same peer IP.
	peerIP := startPkt.SrcIP
	if startPkt.Direction == DirectionResponse {
		peerIP = startPkt.DstIP
	}
	peerFilter := !s.looksLikeSNAT(startPkt.ServiceID, sessionPackets[0].Timestamp)

	// Step 4: find packets containing any token in one bounded query (scoped to
	// the same service). Escaping LIKE metacharacters prevents a token such as
	// "%" or "_" from accidentally matching unrelated sessions.
	sessionIDs := map[string]bool{startPkt.SessionID: true}
	clauses := make([]string, 0, len(tokens))
	args := []interface{}{startPkt.ServiceID, minTS, maxTS}
	for _, token := range tokens {
		if len(token) < 8 || len(token) > 4096 {
			continue // skip very short tokens to avoid false matches
		}
		like := "%" + escapeLike(token) + "%"
		clauses = append(clauses, `(headers LIKE ? ESCAPE '\' OR body_string LIKE ? ESCAPE '\')`)
		args = append(args, like, like)
	}
	if len(clauses) > 0 {
		query := "SELECT " + packetSelectCols + " FROM packets WHERE service_id = ? AND timestamp BETWEEN ? AND ? AND (" + strings.Join(clauses, " OR ") + ")"
		if peerFilter && peerIP != "" {
			query += " AND ((direction = 'request' AND src_ip = ?) OR (direction = 'response' AND dst_ip = ?))"
			args = append(args, peerIP, peerIP)
		}
		query += " ORDER BY timestamp ASC, id ASC LIMIT 500"
		packets, queryErr := s.scanPackets(query, args)
		if queryErr != nil {
			return nil, fmt.Errorf("correlating flow tokens: %w", queryErr)
		}
		for _, packet := range packets {
			if len(sessionIDs) >= 30 {
				break
			}
			if packet.SessionID != "" {
				sessionIDs[packet.SessionID] = true
			}
		}
	}

	// Step 5: fetch all packets from all discovered sessions
	return s.fetchSessions(startPkt.SessionID, sessionIDs, sessionPackets)
}

// exploitRunGap separates distinct exploit "runs" inside a single correlated
// flow. Steps within one run are typically sub-second; repeated runs (e.g. one
// per scoreboard tick, all sharing the victim's session token) are many seconds
// apart, so a few seconds cleanly isolates a single run.
const exploitRunGap = 5 * time.Second

// ExploitFlow returns the packets of the single exploit run that contains the
// given packet.
//
// QueryFlow (used by the flow view) deliberately correlates every connection
// that shares a victim's auth token within ±FlowCorrelationWindowSec — under
// real SNAT this is the only way to reconstruct a multi-connection attack. But
// it also splices together several repetitions of the SAME exploit (the
// attacker re-runs it every tick), and feeding all of them to the exploit
// generator interleaves their steps and corrupts the order (e.g. an earlier
// run's GET ends up before a later run's login).
//
// For generation we therefore keep only the time-contiguous cluster around the
// anchor packet — one coherent run regardless of HTTP keep-alive (one session)
// or connection-close (one session per request). The flow view is unaffected.
func (s *PacketStore) ExploitFlow(packetID int64) ([]*Packet, error) {
	flow, err := s.QueryFlow(packetID)
	if err != nil {
		return nil, err
	}
	if len(flow) < 2 {
		return flow, nil
	}
	// flow is ordered by timestamp ASC. Find the anchor and grow outwards while
	// consecutive packets stay within exploitRunGap of each other.
	anchor := -1
	for i, p := range flow {
		if p.ID == packetID {
			anchor = i
			break
		}
	}
	if anchor < 0 {
		return flow, nil
	}
	lo, hi := anchor, anchor
	for lo > 0 && flow[lo].Timestamp.Sub(flow[lo-1].Timestamp) <= exploitRunGap {
		lo--
	}
	for hi < len(flow)-1 && flow[hi+1].Timestamp.Sub(flow[hi].Timestamp) <= exploitRunGap {
		hi++
	}
	return flow[lo : hi+1], nil
}

// flowByPeerIP correlates sessions from the same source IP to the same service
// within a time window (±30s around the session). Used when no auth tokens are
// available to link connections.
//
// SNAT-aware: in competition networks with source NAT (e.g., CyberChallenge),
// all traffic arrives from the router IP, making peer IP correlation unreliable.
// We detect this by checking IP diversity over a wider window; if only 1 IP
// sends all traffic, we fall back to the single TCP session.
func (s *PacketStore) flowByPeerIP(startPkt *Packet, sessionPackets []*Packet) ([]*Packet, error) {
	// Determine attacker (peer) IP
	peerIP := startPkt.SrcIP
	if startPkt.Direction == DirectionResponse {
		peerIP = startPkt.DstIP
	}
	if peerIP == "" || len(sessionPackets) == 0 {
		return sessionPackets, nil
	}

	// Time window: session range ± configured correlation window
	w := s.flowCorrelationWindow()
	minTime := sessionPackets[0].Timestamp.Add(-w)
	maxTime := sessionPackets[len(sessionPackets)-1].Timestamp.Add(w)

	rows, err := s.rdb.Query(
		`SELECT DISTINCT session_id FROM packets
		 WHERE service_id = ? AND direction = 'request' AND src_ip = ?
		 AND timestamp BETWEEN ? AND ?
		 LIMIT 30`,
		startPkt.ServiceID, peerIP,
		CanonicalTimestamp(minTime),
		CanonicalTimestamp(maxTime),
	)
	if err != nil {
		return sessionPackets, err
	}
	defer rows.Close()

	sessionIDs := map[string]bool{startPkt.SessionID: true}
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err != nil {
			return sessionPackets, err
		}
		if sid != "" {
			sessionIDs[sid] = true
		}
	}
	if err := rows.Err(); err != nil {
		return sessionPackets, err
	}

	// SNAT detection: if multiple sessions share this peer IP, check whether
	// the network uses source NAT (all traffic from a single gateway IP).
	// In SNAT, peer IP correlation is unreliable — fall back to single session.
	if len(sessionIDs) > 1 && s.looksLikeSNAT(startPkt.ServiceID, sessionPackets[0].Timestamp) {
		return sessionPackets, nil
	}

	return s.fetchSessions(startPkt.SessionID, sessionIDs, sessionPackets)
}

// looksLikeSNAT returns true when all request traffic for a service comes from
// a single IP, which strongly suggests the competition network performs source
// NAT (e.g., CyberChallenge cloud router 10.254.0.1 rewrites all src addresses).
// Uses a ±2 minute window around the reference time for a reliable sample.
func (s *PacketStore) looksLikeSNAT(serviceID string, around time.Time) bool {
	wideMin := CanonicalTimestamp(around.Add(-2 * time.Minute))
	wideMax := CanonicalTimestamp(around.Add(2 * time.Minute))

	var totalRequests, distinctIPs int
	err := s.rdb.QueryRow(
		`SELECT COUNT(*), COUNT(DISTINCT src_ip) FROM packets
		 WHERE service_id = ? AND direction = 'request'
		 AND timestamp BETWEEN ? AND ?`,
		serviceID, wideMin, wideMax,
	).Scan(&totalRequests, &distinctIPs)
	if err != nil {
		return false
	}

	// In SNAT, all traffic comes from 1 gateway IP.
	// In normal environments, multiple attacker IPs are visible.
	// Five independent request sessions are enough evidence for this defensive
	// fallback. The previous threshold of ten counted only requests even though
	// it was calibrated against request+response packet counts, so small but
	// realistic SNAT samples were incorrectly merged.
	return totalRequests >= 5 && distinctIPs <= 1
}

// fetchSessions returns packets from all discovered sessions, or the original
// sessionPackets if only one session was found.
func (s *PacketStore) fetchSessions(originalSID string, sessionIDs map[string]bool, sessionPackets []*Packet) ([]*Packet, error) {
	if len(sessionIDs) <= 1 {
		return sessionPackets, nil
	}

	var placeholders []string
	serviceID := sessionPackets[0].ServiceID
	args := []interface{}{serviceID}
	for sid := range sessionIDs {
		placeholders = append(placeholders, "?")
		args = append(args, sid)
	}

	query := "SELECT " + packetSelectCols + " FROM packets WHERE service_id = ? AND session_id IN (" + strings.Join(placeholders, ",") + ") ORDER BY timestamp ASC, id ASC LIMIT 500"
	return s.scanPackets(query, args)
}

// extractAuthTokens extracts Bearer tokens, session cookies, and JSON token
// fields from packet headers and bodies. These values are used to correlate
// packets across TCP connections that belong to the same logical session.
func extractAuthTokens(packets []*Packet) []string {
	const maxTokens = 32
	seen := map[string]bool{}
	var tokens []string

	add := func(v string) {
		if len(tokens) < maxTokens && v != "" && !seen[v] {
			seen[v] = true
			tokens = append(tokens, v)
		}
	}

	for _, p := range packets {
		// Check Authorization header (Bearer tokens)
		if auth, ok := packetHeader(p.Headers, "Authorization"); ok {
			add(extractBearerToken(auth))
		}

		// Check Cookie header (requests) — e.g., "session=abc123; csrftoken=xyz"
		if cookie, ok := packetHeader(p.Headers, "Cookie"); ok {
			for _, v := range extractCookieValues(cookie) {
				add(v)
			}
		}

		// Check Set-Cookie header (responses) — e.g., "session=abc123; Path=/; HttpOnly"
		if p.Direction == DirectionResponse {
			if sc, ok := packetHeader(p.Headers, "Set-Cookie"); ok {
				for _, v := range extractSetCookieValues(sc) {
					add(v)
				}
			}
		}

		// Check body for token fields in JSON responses (e.g., {"token":"xxx"})
		if p.Direction == DirectionResponse && p.BodyString != "" {
			for _, t := range extractJSONTokens(p.BodyString) {
				add(t)
			}
		}
	}

	return tokens
}

// extractBearerToken extracts the token from "Bearer xxx" or "Bearer: xxx" format.
func extractBearerToken(auth string) string {
	auth = strings.TrimSpace(auth)
	parts := strings.Fields(strings.Replace(auth, ":", " ", 1))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

func packetHeader(headers map[string]string, name string) (string, bool) {
	for key, value := range headers {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

// extractJSONTokens extracts token values from JSON body strings.
var tokenKeyRegex = regexp.MustCompile(`"token"\s*:\s*"([^"]+)"`)

func extractJSONTokens(body string) []string {
	matches := tokenKeyRegex.FindAllStringSubmatch(body, -1)
	var tokens []string
	for _, m := range matches {
		if len(m) > 1 && len(m[1]) >= 8 {
			tokens = append(tokens, m[1])
		}
	}
	return tokens
}

// extractCookieValues parses a Cookie request header and returns values ≥8 chars.
// Format: name1=value1; name2=value2
func extractCookieValues(header string) []string {
	var values []string
	for _, pair := range strings.Split(header, ";") {
		pair = strings.TrimSpace(pair)
		if eq := strings.IndexByte(pair, '='); eq >= 0 {
			val := strings.TrimSpace(pair[eq+1:])
			if len(val) >= 8 {
				values = append(values, val)
			}
		}
	}
	return values
}

// extractSetCookieValues parses Set-Cookie response header(s) and returns values ≥8 chars.
// Multiple Set-Cookie headers may be joined with ", " by flattenHeaders.
// Format per cookie: name=value; Path=/; HttpOnly
func extractSetCookieValues(header string) []string {
	var values []string
	for _, cookie := range splitSetCookieHeader(header) {
		cookie = strings.TrimSpace(cookie)
		// Take only the name=value part (before first ";")
		if semi := strings.IndexByte(cookie, ';'); semi >= 0 {
			cookie = cookie[:semi]
		}
		cookie = strings.TrimSpace(cookie)
		if eq := strings.IndexByte(cookie, '='); eq >= 0 {
			val := strings.TrimSpace(cookie[eq+1:])
			if len(val) >= 8 {
				values = append(values, val)
			}
		}
	}
	return values
}

func splitSetCookieHeader(header string) []string {
	var out []string
	start := 0
	quoted := false
	for i := 0; i < len(header); i++ {
		switch header[i] {
		case '"':
			quoted = !quoted
		case ',':
			if quoted {
				continue
			}
			j := i + 1
			for j < len(header) && (header[j] == ' ' || header[j] == '\t') {
				j++
			}
			nameStart := j
			for j < len(header) && isCookieNameByte(header[j]) {
				j++
			}
			if j > nameStart && j < len(header) && header[j] == '=' {
				out = append(out, strings.TrimSpace(header[start:i]))
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(header[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

func isCookieNameByte(b byte) bool {
	if b <= 0x20 || b >= 0x7f {
		return false
	}
	return !strings.ContainsRune("()<>@,;:\\\"/[]?={}", rune(b))
}

func escapeLike(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}

// headerSearchPattern builds a SQL LIKE pattern for searching headers.
// Headers are stored as a JSON object like {"X-Powered-By":"Express","Content-Type":"application/json"}.
// If the query contains a colon ("Name: Value"), it's split so users can paste header lines
// as they see them on screen. Otherwise a plain substring is used.
func headerSearchPattern(q string) string {
	if idx := strings.Index(q, ":"); idx > 0 {
		name := strings.TrimSpace(q[:idx])
		value := strings.TrimSpace(q[idx+1:])
		if name != "" {
			if value == "" {
				return "%\"" + escapeLike(name) + "\"%"
			}
			return "%\"" + escapeLike(name) + "\"%" + escapeLike(value) + "%"
		}
	}
	return "%" + escapeLike(q) + "%"
}

// buildWhereAndResidual extends buildWhere with the DSL filter (q.Q).
// Pushable predicates are AND-merged into the SQL WHERE; the rest are
// returned as an in-process evaluator the caller runs after the fetch.
func buildWhereAndResidual(q PacketQuery) (string, []interface{}, filter.EvalFunc, error) {
	where, args := buildWhere(q)
	if strings.TrimSpace(q.Q) == "" {
		return where, args, nil, nil
	}
	ast, err := filter.Parse(q.Q)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid q expression: %w", err)
	}
	c, err := filter.CompileSQL(ast)
	if err != nil {
		return "", nil, nil, fmt.Errorf("invalid q expression: %w", err)
	}
	if c.Where != "" {
		if where == "" {
			where = " WHERE " + c.Where
		} else {
			where += " AND " + c.Where
		}
		args = append(args, c.Args...)
	}
	return where, args, c.Residual, nil
}

func buildWhere(q PacketQuery) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if q.ServiceID != "" {
		conditions = append(conditions, "service_id = ?")
		args = append(args, q.ServiceID)
	}
	if len(q.ServiceIDs) > 0 {
		placeholders := make([]string, len(q.ServiceIDs))
		for i, serviceID := range q.ServiceIDs {
			placeholders[i] = "?"
			args = append(args, serviceID)
		}
		conditions = append(conditions, "service_id IN ("+strings.Join(placeholders, ",")+")")
	}
	if q.SessionID != "" {
		conditions = append(conditions, "session_id = ?")
		args = append(args, q.SessionID)
	}
	if q.SrcIP != "" {
		conditions = append(conditions, "src_ip = ?")
		args = append(args, q.SrcIP)
	}
	if q.DstIP != "" {
		conditions = append(conditions, "dst_ip = ?")
		args = append(args, q.DstIP)
	}
	if q.Protocol != "" {
		conditions = append(conditions, "protocol = ?")
		args = append(args, q.Protocol)
	}
	if q.Method != "" {
		conditions = append(conditions, "method = ?")
		args = append(args, q.Method)
	}
	if q.Direction != "" {
		conditions = append(conditions, "direction = ?")
		args = append(args, q.Direction)
	}
	if q.PeerIP != "" {
		// Peer IP: the external party — src_ip on requests, dst_ip on responses
		conditions = append(conditions, "((direction = 'request' AND src_ip = ?) OR (direction = 'response' AND dst_ip = ?))")
		args = append(args, q.PeerIP, q.PeerIP)
	}
	if q.TimeFrom != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, CanonicalTimestamp(*q.TimeFrom))
	}
	if q.TimeTo != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, CanonicalTimestamp(*q.TimeTo))
	}
	if q.URL != "" {
		conditions = append(conditions, `url LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(q.URL)+"%")
	}
	if q.Contains != "" {
		conditions = append(conditions, `(body_string LIKE ? ESCAPE '\' OR headers LIKE ? ESCAPE '\' OR url LIKE ? ESCAPE '\')`)
		like := "%" + escapeLike(q.Contains) + "%"
		args = append(args, like, like, like)
	}
	if q.ContainsBody != "" {
		conditions = append(conditions, `body_string LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(q.ContainsBody)+"%")
	}
	if q.ContainsHeaders != "" {
		conditions = append(conditions, `headers LIKE ? ESCAPE '\'`)
		args = append(args, headerSearchPattern(q.ContainsHeaders))
	}
	// Negation conditions
	if q.NotServiceID != "" {
		conditions = append(conditions, "service_id != ?")
		args = append(args, q.NotServiceID)
	}
	if q.NotSrcIP != "" {
		conditions = append(conditions, "src_ip != ?")
		args = append(args, q.NotSrcIP)
	}
	if q.NotDstIP != "" {
		conditions = append(conditions, "dst_ip != ?")
		args = append(args, q.NotDstIP)
	}
	if q.NotProtocol != "" {
		conditions = append(conditions, "protocol != ?")
		args = append(args, q.NotProtocol)
	}
	if q.NotMethod != "" {
		conditions = append(conditions, "method != ?")
		args = append(args, q.NotMethod)
	}
	if q.NotDirection != "" {
		conditions = append(conditions, "direction != ?")
		args = append(args, q.NotDirection)
	}
	if q.NotPeerIP != "" {
		conditions = append(conditions, "NOT ((direction = 'request' AND src_ip = ?) OR (direction = 'response' AND dst_ip = ?))")
		args = append(args, q.NotPeerIP, q.NotPeerIP)
	}
	if q.NotURL != "" {
		conditions = append(conditions, `url NOT LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(q.NotURL)+"%")
	}
	if q.NotContains != "" {
		conditions = append(conditions, `NOT (body_string LIKE ? ESCAPE '\' OR headers LIKE ? ESCAPE '\' OR url LIKE ? ESCAPE '\')`)
		like := "%" + escapeLike(q.NotContains) + "%"
		args = append(args, like, like, like)
	}
	if q.NotContainsBody != "" {
		conditions = append(conditions, `body_string NOT LIKE ? ESCAPE '\'`)
		args = append(args, "%"+escapeLike(q.NotContainsBody)+"%")
	}
	if q.NotContainsHeaders != "" {
		conditions = append(conditions, `headers NOT LIKE ? ESCAPE '\'`)
		args = append(args, headerSearchPattern(q.NotContainsHeaders))
	}
	if q.Flagged != nil {
		if *q.Flagged {
			conditions = append(conditions, "flagged = 1")
		} else {
			conditions = append(conditions, "flagged = 0")
		}
	}
	if q.ContainsFlagID != nil {
		if *q.ContainsFlagID {
			conditions = append(conditions, "contains_flagid = 1")
		} else {
			conditions = append(conditions, "contains_flagid = 0")
		}
	}
	if q.FlagIDRound != nil {
		conditions = append(conditions, "flagid_round = ?")
		args = append(args, *q.FlagIDRound)
	}
	if q.HasMatchedRules != nil {
		if *q.HasMatchedRules {
			conditions = append(conditions, "matched_rules != '[]'")
		} else {
			conditions = append(conditions, "matched_rules = '[]'")
		}
	}
	if q.Dropped != nil {
		// Fast path: indexed column computed at ingestion time.
		if *q.Dropped {
			conditions = append(conditions, "has_drop_match = 1")
		} else {
			conditions = append(conditions, "has_drop_match = 0")
		}
	}
	if q.HiddenBefore != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, CanonicalTimestamp(*q.HiddenBefore))
	}
	if len(q.ExcludeIDs) > 0 {
		placeholders := make([]string, len(q.ExcludeIDs))
		for i, id := range q.ExcludeIDs {
			placeholders[i] = "?"
			args = append(args, id)
		}
		conditions = append(conditions, "id NOT IN ("+strings.Join(placeholders, ",")+")")
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}
