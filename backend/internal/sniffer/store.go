package sniffer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/SimoneErrigo/Janus/backend/internal/filter"
	_ "modernc.org/sqlite"
)

// packetSelectCols is the standard column list for packet SELECTs.
const packetSelectCols = "id, service_id, session_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, direction, method, url, status, headers, body, body_string, matched_rules, flagged, contains_flagid, matched_flagids, flagid_round"

// packetSummaryCols is the slim column list for list-view queries: skips
// body (raw blob), body_string (returned truncated via substr below), and
// matched_flagids JSON. Headers are still selected because the row cell
// preview falls back to body_string substring when URL is empty.
const packetSummaryCols = "id, service_id, session_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, direction, method, url, status, substr(body_string, 1, 80), matched_rules, flagged, contains_flagid, flagid_round"

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

	flowCorrelationWindowSec atomic.Int64

	// Async batched writer for the proxy hot path. Enqueue() pushes here;
	// a single goroutine drains and writes batches via multi-row INSERT.
	queue   chan batchItem
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// batchItem carries a packet and any alerts that must be linked to it.
// The alerts have PacketID unset; the writer fills it in once the packet ID is known.
type batchItem struct {
	pkt    *Packet
	alerts []*Alert
}

const (
	packetQueueSize    = 8192
	packetBatchMax     = 64
	packetBatchFlushMs = 25
)

// NewPacketStore opens (or creates) the SQLite database at dataDir/packets.db.
func NewPacketStore(dataDir string) (*PacketStore, error) {
	dbPath := filepath.Join(dataDir, "packets.db")
	connStr := dbPath + "?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=30000&_cache_size=-32000"

	// Writer connection: single conn to serialize INSERTs/UPDATEs/DELETEs
	db, err := sql.Open("sqlite", connStr)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite writer: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	// Reader connection pool: multiple conns for concurrent SELECTs
	// WAL mode allows concurrent readers even while a write is in progress
	rdb, err := sql.Open("sqlite", connStr+"&mode=ro")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("opening sqlite reader: %w", err)
	}
	rdb.SetMaxOpenConns(4)
	rdb.SetMaxIdleConns(4)

	if err := migrate(db); err != nil {
		db.Close()
		rdb.Close()
		return nil, fmt.Errorf("migrating sqlite: %w", err)
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
	go ps.runBatchWriter()
	return ps, nil
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

// SetPacketChangeListener is called when new packets are inserted or metadata is bulk-updated
// (e.g. flag-ID backfill). The callback must be non-blocking; it is invoked synchronously from Insert.
func (s *PacketStore) SetPacketChangeListener(fn func(PacketChangeKind, *Packet)) {
	s.muChange.Lock()
	defer s.muChange.Unlock()
	s.onChange = fn
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
			matched_rules    TEXT    NOT NULL DEFAULT '[]',
			flagged          INTEGER NOT NULL DEFAULT 0,
			contains_flagid  INTEGER NOT NULL DEFAULT 0,
			has_drop_match   INTEGER NOT NULL DEFAULT 0
		);
		CREATE INDEX IF NOT EXISTS idx_packets_service_id ON packets(service_id);
		CREATE INDEX IF NOT EXISTS idx_packets_timestamp  ON packets(timestamp);
		CREATE INDEX IF NOT EXISTS idx_packets_src_ip     ON packets(src_ip);
		CREATE INDEX IF NOT EXISTS idx_packets_dst_ip     ON packets(dst_ip);
		CREATE INDEX IF NOT EXISTS idx_packets_protocol   ON packets(protocol);
		CREATE INDEX IF NOT EXISTS idx_packets_flagged    ON packets(flagged);
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
		"ALTER TABLE packets ADD COLUMN matched_flagids TEXT NOT NULL DEFAULT '[]'",
		"ALTER TABLE packets ADD COLUMN flagid_round INTEGER NOT NULL DEFAULT 0",
		"ALTER TABLE packets ADD COLUMN has_drop_match INTEGER NOT NULL DEFAULT 0",
		// inserted_at tracks when the row was added to *this* DB, distinct
		// from the wire timestamp. Cleanup-by-age uses it so imports of old
		// PCAPs aren't immediately wiped just because their capture clock
		// is in the past.
		"ALTER TABLE packets ADD COLUMN inserted_at TEXT NOT NULL DEFAULT ''",
	} {
		db.Exec(col) // ignore "duplicate column" errors
	}

	// One-time backfill: rows present before the inserted_at column existed
	// get inserted_at = timestamp so the cutoff comparison stays meaningful
	// for them. New inserts populate the column directly.
	db.Exec("UPDATE packets SET inserted_at = timestamp WHERE inserted_at = ''")

	// Create indexes for columns added by migrations (must run after ALTER TABLE)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_packets_session_id ON packets(session_id)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_packets_contains_flagid ON packets(contains_flagid)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_packets_has_drop_match ON packets(has_drop_match)")

	// Composite index for the most common query: filter by service + sort by time
	db.Exec("CREATE INDEX IF NOT EXISTS idx_packets_service_ts ON packets(service_id, timestamp DESC)")

	// Composite index for backfill: find recent unmarked packets quickly
	db.Exec("CREATE INDEX IF NOT EXISTS idx_packets_backfill ON packets(contains_flagid, timestamp)")

	// Index for smart backfill: find packets scanned with older AC automaton
	db.Exec("CREATE INDEX IF NOT EXISTS idx_packets_flagid_round ON packets(flagid_round, timestamp)")

	// Cleanup-by-age and cleanup-by-size both order on inserted_at.
	db.Exec("CREATE INDEX IF NOT EXISTS idx_packets_inserted_at ON packets(inserted_at)")

	// Backfill existing rows once after migration.
	// A row is considered dropped if any matched rule has action drop/both.
	db.Exec("UPDATE packets SET has_drop_match = CASE WHEN (matched_rules LIKE '%\"action\":\"drop\"%' OR matched_rules LIKE '%\"action\":\"both\"%') THEN 1 ELSE 0 END WHERE has_drop_match = 0")

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
	`)
	if err != nil {
		return err
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

	// Snapshot of full packet data per saved flow — survives packet purges so
	// pinned flows remain inspectable after the packets table is wiped.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS saved_flow_packets (
			saved_flow_id INTEGER NOT NULL,
			ordinal       INTEGER NOT NULL,
			packet_id     INTEGER NOT NULL,
			data          BLOB    NOT NULL,
			PRIMARY KEY (saved_flow_id, ordinal)
		);
		CREATE INDEX IF NOT EXISTS idx_sfp_flow ON saved_flow_packets(saved_flow_id);
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

// execInsertRetry retries Exec on SQLITE_BUSY (backfill vs proxy traffic).
func (s *PacketStore) execInsertRetry(query string, args ...interface{}) (sql.Result, error) {
	var res sql.Result
	var err error
	for attempt := 0; attempt < 12; attempt++ {
		res, err = s.db.Exec(query, args...)
		if err == nil {
			return res, nil
		}
		if !isSQLiteBusy(err) {
			return nil, err
		}
		time.Sleep(time.Duration(3+attempt*4) * time.Millisecond)
	}
	return nil, err
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
	autoFillBodyString(p)

	headersJSON, err := json.Marshal(p.Headers)
	if err != nil {
		headersJSON = []byte("{}")
	}

	matchedRulesJSON, err := json.Marshal(p.MatchedRules)
	if err != nil {
		matchedRulesJSON = []byte("[]")
	}

	flaggedInt := 0
	if p.Flagged {
		flaggedInt = 1
	}
	containsFlagIDInt := 0
	if p.ContainsFlagID {
		containsFlagIDInt = 1
	}
	hasDropMatchInt := 0
	for _, r := range p.MatchedRules {
		switch r.Action {
		case "drop", "both":
			hasDropMatchInt = 1
		}
	}

	if p.MatchedFlagIDs == nil {
		p.MatchedFlagIDs = []string{}
	}
	matchedFlagIDsJSON, err := json.Marshal(p.MatchedFlagIDs)
	if err != nil {
		matchedFlagIDsJSON = []byte("[]")
	}

	insertedAt := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.execInsertRetry(`
		INSERT INTO packets (service_id, session_id, timestamp, src_ip, src_port, dst_ip, dst_port,
			protocol, direction, method, url, status, headers, body, body_string,
			matched_rules, flagged, contains_flagid, matched_flagids, flagid_round, has_drop_match,
			inserted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ServiceID, p.SessionID,
		p.Timestamp.UTC().Format(time.RFC3339Nano),
		p.SrcIP, p.SrcPort,
		p.DstIP, p.DstPort,
		p.Protocol, p.Direction,
		p.Method, p.URL, p.Status,
		string(headersJSON),
		p.Body, p.BodyString,
		string(matchedRulesJSON), flaggedInt, containsFlagIDInt,
		string(matchedFlagIDsJSON), p.FlagIDRound, hasDropMatchInt,
		insertedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting packet: %w", err)
	}

	id, _ := res.LastInsertId()
	p.ID = id
	s.emitChange(PacketChangeInsert, p)
	return nil
}

// Enqueue submits a packet (and any linked alerts whose PacketID will be filled
// in by the writer) to the async batched writer. Falls back to a synchronous
// Insert if the queue is full or the writer has been shut down.
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
	select {
	case s.queue <- batchItem{pkt: pkt, alerts: alerts}:
		return nil
	default:
	}
	// Queue full — fall back to sync insert so we don't drop packets under load.
	if err := s.Insert(pkt); err != nil {
		return err
	}
	for _, a := range alerts {
		a.PacketID = pkt.ID
		if err := s.InsertAlert(a); err != nil {
			return err
		}
	}
	return nil
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
	const packetCols = 22
	rowPlaceholder := "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
	placeholders := make([]string, len(batch))
	args := make([]interface{}, 0, len(batch)*packetCols)
	insertedAt := time.Now().UTC().Format(time.RFC3339Nano)
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
		matchedFlagIDsJSON, err := json.Marshal(p.MatchedFlagIDs)
		if err != nil {
			matchedFlagIDsJSON = []byte("[]")
		}

		flaggedInt := 0
		if p.Flagged {
			flaggedInt = 1
		}
		containsFlagIDInt := 0
		if p.ContainsFlagID {
			containsFlagIDInt = 1
		}
		hasDropMatchInt := 0
		for _, r := range p.MatchedRules {
			switch r.Action {
			case "drop", "both":
				hasDropMatchInt = 1
			}
		}

		args = append(args,
			p.ServiceID, p.SessionID,
			p.Timestamp.UTC().Format(time.RFC3339Nano),
			p.SrcIP, p.SrcPort,
			p.DstIP, p.DstPort,
			p.Protocol, p.Direction,
			p.Method, p.URL, p.Status,
			string(headersJSON),
			p.Body, p.BodyString,
			string(matchedRulesJSON), flaggedInt, containsFlagIDInt,
			string(matchedFlagIDsJSON), p.FlagIDRound, hasDropMatchInt,
			insertedAt,
		)
	}

	query := `INSERT INTO packets (service_id, session_id, timestamp, src_ip, src_port, dst_ip, dst_port,
		protocol, direction, method, url, status, headers, body, body_string,
		matched_rules, flagged, contains_flagid, matched_flagids, flagid_round, has_drop_match,
		inserted_at)
		VALUES ` + strings.Join(placeholders, ",")

	res, err := s.execInsertRetry(query, args...)
	if err != nil {
		// Batch failed — fall back to one-by-one Insert (and InsertAlert) so we
		// don't drop captures wholesale.
		for _, it := range batch {
			if ierr := s.Insert(it.pkt); ierr != nil {
				continue
			}
			for _, a := range it.alerts {
				a.PacketID = it.pkt.ID
				_ = s.InsertAlert(a)
			}
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
				a.Timestamp.UTC().Format(time.RFC3339Nano),
				a.PatternMatched,
			)
		}
	}
	if len(alertPlaceholders) > 0 {
		alertQuery := `INSERT INTO alerts (packet_id, rule_id, service_id, src_ip, timestamp, pattern_matched) VALUES ` +
			strings.Join(alertPlaceholders, ",")
		if _, err := s.execInsertRetry(alertQuery, alertArgs...); err != nil {
			// Best-effort retry per-row so we don't lose alerts on a single bad input
			for _, it := range batch {
				for _, a := range it.alerts {
					_ = s.InsertAlert(a)
				}
			}
		}
	}

	// --- Notify SSE for each newly-inserted packet ---
	for _, it := range batch {
		s.emitChange(PacketChangeInsert, it.pkt)
	}
}

// Query retrieves packets matching the given filters.
// The regex filter and any DSL-residual predicates are applied in Go after
// the SQL query for correct pagination.
func (s *PacketStore) Query(q PacketQuery) ([]*Packet, int, error) {
	where, args, residual, err := buildWhereAndResidual(q)
	if err != nil {
		return nil, 0, err
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
		// Fetch all SQL-matching rows, filter in Go (regex + residual), paginate.
		return s.queryWithGoFilter(q, where, args, selectCols, sortOrder, limit, offset, residual)
	}

	// Fetch the page first, then only run COUNT(*) if it's cheap. COUNT on LIKE
	// predicates over body_string/headers is a full table scan and dominates
	// query time — in practice the UI only needs a bound ("is there another
	// page?") so we skip the expensive COUNT and estimate total.
	querySQL := "SELECT " + selectCols + " FROM packets" +
		where + " ORDER BY timestamp " + sortOrder + " LIMIT ? OFFSET ?"
	queryArgs := append(args, limit, offset)

	var packets []*Packet
	if useSummary {
		packets, err = s.scanPacketsSummary(querySQL, queryArgs)
	} else {
		packets, err = s.scanPackets(querySQL, queryArgs)
	}
	if err != nil {
		return nil, 0, err
	}

	total, err := s.countOrEstimate(q, where, args, offset, len(packets), limit)
	if err != nil {
		return nil, 0, err
	}
	return packets, total, nil
}

// countOrEstimate returns the exact COUNT(*) when the predicate is cheap, or an
// estimated total otherwise. "Cheap" = no wildcard LIKE / negation text scans.
// The estimate is tight enough for infinite-scroll (offset + returned ± 1).
func (s *PacketStore) countOrEstimate(q PacketQuery, where string, args []interface{}, offset, returned, limit int) (int, error) {
	if isExpensiveTextPredicate(q) {
		// Estimate: the backend doesn't know the true total without a full scan.
		// Return offset+returned when the page isn't full (we've reached the end),
		// otherwise offset+returned+1 to signal "more available" to the client.
		if returned < limit {
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
		q.URL != "" || q.NotURL != ""
}

// queryWithGoFilter fetches SQL-filtered rows, applies regex/not-regex and any
// DSL residual evaluator in Go, then paginates. Used whenever post-SQL
// filtering is required.
func (s *PacketStore) queryWithGoFilter(q PacketQuery, where string, args []interface{}, selectCols, sortOrder string, limit, offset int, residual filter.EvalFunc) ([]*Packet, int, error) {
	var re, notRe *regexp.Regexp
	if q.Regex != "" {
		var err error
		re, err = regexp.Compile(q.Regex)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid regex: %w", err)
		}
	}
	if q.NotRegex != "" {
		var err error
		notRe, err = regexp.Compile(q.NotRegex)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid not_regex: %w", err)
		}
	}

	querySQL := "SELECT " + selectCols + " FROM packets" +
		where + " ORDER BY timestamp " + sortOrder

	allPackets, err := s.scanPackets(querySQL, args)
	if err != nil {
		return nil, 0, err
	}

	// Apply regex / not-regex / DSL-residual filters
	var filtered []*Packet
	for _, p := range allPackets {
		if re != nil && !regexMatchesPacket(re, p) {
			continue
		}
		if notRe != nil && regexMatchesPacket(notRe, p) {
			continue
		}
		if residual != nil && !residual(AsView(p)) {
			continue
		}
		filtered = append(filtered, p)
	}

	total := len(filtered)

	// Paginate
	if offset >= len(filtered) {
		return []*Packet{}, total, nil
	}
	end := offset + limit
	if end > len(filtered) {
		end = len(filtered)
	}

	return filtered[offset:end], total, nil
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
		var flaggedInt, containsFlagIDInt int
		if err := rows.Scan(
			&p.ID, &p.ServiceID, &p.SessionID, &ts,
			&p.SrcIP, &p.SrcPort, &p.DstIP, &p.DstPort,
			&p.Protocol, &p.Direction,
			&p.Method, &p.URL, &p.Status,
			&headersJSON, &p.Body, &p.BodyString,
			&matchedRulesJSON, &flaggedInt, &containsFlagIDInt,
			&matchedFlagIDsJSON, &p.FlagIDRound,
		); err != nil {
			return nil, fmt.Errorf("scanning packet: %w", err)
		}

		p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		p.Flagged = flaggedInt != 0
		p.ContainsFlagID = containsFlagIDInt != 0

		if headersJSON != "" && headersJSON != "{}" {
			json.Unmarshal([]byte(headersJSON), &p.Headers)
		}

		if matchedRulesJSON != "" && matchedRulesJSON != "[]" {
			json.Unmarshal([]byte(matchedRulesJSON), &p.MatchedRules)
		}

		if matchedFlagIDsJSON != "" && matchedFlagIDsJSON != "[]" {
			json.Unmarshal([]byte(matchedFlagIDsJSON), &p.MatchedFlagIDs)
		}

		if p.MatchedRules == nil {
			p.MatchedRules = []MatchedRuleInfo{}
		}
		if p.MatchedFlagIDs == nil {
			p.MatchedFlagIDs = []string{}
		}

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
		var ts, bodyPreview, matchedRulesJSON string
		var flaggedInt, containsFlagIDInt int
		if err := rows.Scan(
			&p.ID, &p.ServiceID, &p.SessionID, &ts,
			&p.SrcIP, &p.SrcPort, &p.DstIP, &p.DstPort,
			&p.Protocol, &p.Direction,
			&p.Method, &p.URL, &p.Status,
			&bodyPreview,
			&matchedRulesJSON, &flaggedInt, &containsFlagIDInt,
			&p.FlagIDRound,
		); err != nil {
			return nil, fmt.Errorf("scanning packet summary: %w", err)
		}

		p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		p.Flagged = flaggedInt != 0
		p.ContainsFlagID = containsFlagIDInt != 0
		p.BodyString = bodyPreview

		if matchedRulesJSON != "" && matchedRulesJSON != "[]" {
			json.Unmarshal([]byte(matchedRulesJSON), &p.MatchedRules)
		}
		if p.MatchedRules == nil {
			p.MatchedRules = []MatchedRuleInfo{}
		}
		p.MatchedFlagIDs = []string{}

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
	var flaggedInt, containsFlagIDInt int
	if err := row.Scan(
		&p.ID, &p.ServiceID, &p.SessionID, &ts,
		&p.SrcIP, &p.SrcPort, &p.DstIP, &p.DstPort,
		&p.Protocol, &p.Direction,
		&p.Method, &p.URL, &p.Status,
		&headersJSON, &p.Body, &p.BodyString,
		&matchedRulesJSON, &flaggedInt, &containsFlagIDInt,
		&matchedFlagIDsJSON, &p.FlagIDRound,
	); err != nil {
		return nil, err
	}

	p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	p.Flagged = flaggedInt != 0
	p.ContainsFlagID = containsFlagIDInt != 0

	if headersJSON != "" && headersJSON != "{}" {
		json.Unmarshal([]byte(headersJSON), &p.Headers)
	}
	if matchedRulesJSON != "" && matchedRulesJSON != "[]" {
		json.Unmarshal([]byte(matchedRulesJSON), &p.MatchedRules)
	}
	if matchedFlagIDsJSON != "" && matchedFlagIDsJSON != "[]" {
		json.Unmarshal([]byte(matchedFlagIDsJSON), &p.MatchedFlagIDs)
	}
	if p.MatchedRules == nil {
		p.MatchedRules = []MatchedRuleInfo{}
	}
	if p.MatchedFlagIDs == nil {
		p.MatchedFlagIDs = []string{}
	}

	return p, nil
}

// InsertAlert stores an alert in the database.
func (s *PacketStore) InsertAlert(a *Alert) error {
	res, err := s.execInsertRetry(`
		INSERT INTO alerts (packet_id, rule_id, service_id, src_ip, timestamp, pattern_matched)
		VALUES (?, ?, ?, ?, ?, ?)`,
		a.PacketID, a.RuleID, a.ServiceID, a.SrcIP,
		a.Timestamp.UTC().Format(time.RFC3339Nano),
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
		args = append(args, q.TimeFrom.UTC().Format(time.RFC3339Nano))
	}
	if q.TimeTo != nil {
		conditions = append(conditions, "a.timestamp <= ?")
		args = append(args, q.TimeTo.UTC().Format(time.RFC3339Nano))
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
		where + " ORDER BY a.timestamp DESC LIMIT ? OFFSET ?"
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
		sf.CreatedAt.UTC().Format(time.RFC3339Nano), sf.Notes,
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
	res, err := s.db.Exec("DELETE FROM saved_flows WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("saved flow not found")
	}
	// Best-effort cleanup of the snapshot rows; leftover rows would just sit unused.
	_, _ = s.db.Exec("DELETE FROM saved_flow_packets WHERE saved_flow_id = ?", id)
	return nil
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
	res, err := s.db.Exec("DELETE FROM alerts")
	if err != nil {
		return 0, 0, fmt.Errorf("deleting all alerts: %w", err)
	}
	alertsDeleted, _ = res.RowsAffected()

	res, err = s.db.Exec("DELETE FROM packets")
	if err != nil {
		return 0, alertsDeleted, fmt.Errorf("deleting all packets: %w", err)
	}
	packetsDeleted, _ = res.RowsAffected()

	// Reclaim disk space
	s.db.Exec("VACUUM")

	return packetsDeleted, alertsDeleted, nil
}

// PurgePackets deletes all packets (and their associated alerts) but preserves
// standalone alert configuration. Returns the number of packets deleted.
func (s *PacketStore) PurgePackets() (int64, error) {
	// Delete alerts that reference packets first (FK-safe)
	s.db.Exec("DELETE FROM alerts")

	res, err := s.db.Exec("DELETE FROM packets")
	if err != nil {
		return 0, fmt.Errorf("deleting all packets: %w", err)
	}
	n, _ := res.RowsAffected()

	s.db.Exec("VACUUM")
	return n, nil
}

// DeletePacketIDs deletes the specified packets and their linked alerts.
// Returns the number of packets actually deleted.
func (s *PacketStore) DeletePacketIDs(ids []int64) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = placeholders[:len(placeholders)-1]
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	// Remove linked alerts first (best-effort)
	_, _ = s.db.Exec("DELETE FROM alerts WHERE packet_id IN ("+placeholders+")", args...)
	// Delete the packets
	res, err := s.db.Exec("DELETE FROM packets WHERE id IN ("+placeholders+")", args...)
	if err != nil {
		return 0, fmt.Errorf("deleting packets by ID: %w", err)
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.emitChange(PacketChangeMetadata, nil)
	}
	return n, nil
}

// PurgeDroppedPackets deletes all packets that were dropped by a rule (has_drop_match=1)
// and their associated alerts. Returns the number of packets deleted.
func (s *PacketStore) PurgeDroppedPackets() (int64, error) {
	s.db.Exec("DELETE FROM alerts WHERE packet_id IN (SELECT id FROM packets WHERE has_drop_match = 1)")

	res, err := s.db.Exec("DELETE FROM packets WHERE has_drop_match = 1")
	if err != nil {
		return 0, fmt.Errorf("deleting dropped packets: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// DeleteOlderThan deletes packets (and their alerts) whose *insertion time*
// is older than the given cutoff. Cleanup uses inserted_at — not the wire
// timestamp — so importing an old PCAP doesn't immediately make every row
// eligible for deletion just because the capture clock is in the past.
func (s *PacketStore) DeleteOlderThan(before time.Time) (packetsDeleted, alertsDeleted int64, err error) {
	ts := before.UTC().Format(time.RFC3339Nano)

	// Delete alerts for packets that will be removed
	res, err := s.db.Exec("DELETE FROM alerts WHERE packet_id IN (SELECT id FROM packets WHERE inserted_at < ?)", ts)
	if err != nil {
		return 0, 0, fmt.Errorf("deleting old alerts: %w", err)
	}
	alertsDeleted, _ = res.RowsAffected()

	res, err = s.db.Exec("DELETE FROM packets WHERE inserted_at < ?", ts)
	if err != nil {
		return 0, alertsDeleted, fmt.Errorf("deleting old packets: %w", err)
	}
	packetsDeleted, _ = res.RowsAffected()

	return packetsDeleted, alertsDeleted, nil
}

// DeleteOldestUntilSize deletes the oldest packets (and their alerts) until the DB is below maxSizeBytes.
// Returns the number of rows deleted from each table.
func (s *PacketStore) DeleteOldestUntilSize(maxSizeBytes int64) (packetsDeleted, alertsDeleted int64, err error) {
	for {
		size, sizeErr := s.DBSize()
		if sizeErr != nil {
			return packetsDeleted, alertsDeleted, sizeErr
		}
		if size <= maxSizeBytes {
			return packetsDeleted, alertsDeleted, nil
		}

		// Delete a batch of oldest packets — ordering by inserted_at so the
		// "oldest" set is what was added to this DB first, not what was
		// captured first on the wire.
		const batchSize = 1000
		res, execErr := s.db.Exec(`
			DELETE FROM alerts WHERE packet_id IN (
				SELECT id FROM packets ORDER BY inserted_at ASC LIMIT ?
			)`, batchSize)
		if execErr != nil {
			return packetsDeleted, alertsDeleted, fmt.Errorf("batch deleting alerts: %w", execErr)
		}
		ad, _ := res.RowsAffected()
		alertsDeleted += ad

		res, execErr = s.db.Exec("DELETE FROM packets WHERE id IN (SELECT id FROM packets ORDER BY inserted_at ASC LIMIT ?)", batchSize)
		if execErr != nil {
			return packetsDeleted, alertsDeleted, fmt.Errorf("batch deleting packets: %w", execErr)
		}
		pd, _ := res.RowsAffected()
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

	// Only backfill packets from the last 60 seconds (the limbo between round start
	// and flagId fetch completion). Older packets were already scanned with the
	// automaton that was current at their insertion time.
	cutoff := time.Now().Add(-60 * time.Second).UTC().Format(time.RFC3339Nano)

	var total int64
	const batchSize = 500
	const updateChunk = 32

	for {
		rows, err := s.db.Query(
			"SELECT id, body_string, url, headers FROM packets WHERE flagid_round < ? AND timestamp >= ? ORDER BY id ASC LIMIT ?",
			currentRound, cutoff, batchSize,
		)
		if err != nil {
			return total, fmt.Errorf("smart backfill select: %w", err)
		}

		type pktUpdate struct {
			id      int64
			matched []string
		}
		var updates []pktUpdate
		var markProcessed []int64 // packets with no match, just update flagid_round

		for rows.Next() {
			var id int64
			var bodyStr, url, headers string
			if err := rows.Scan(&id, &bodyStr, &url, &headers); err != nil {
				rows.Close()
				return total, fmt.Errorf("smart backfill scan: %w", err)
			}
			text := url + " " + headers + " " + bodyStr
			matches := checker.FindMatchingFlagIDs(text)
			if len(matches) > 0 {
				vals := make([]string, len(matches))
				for i, m := range matches {
					vals[i] = m.FlagID
				}
				updates = append(updates, pktUpdate{id: id, matched: vals})
			} else {
				markProcessed = append(markProcessed, id)
			}
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
			allOps = append(allOps, pktUpdate{id: id, matched: nil})
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
			for _, op := range allOps[chunkStart:chunkEnd] {
				if op.matched != nil {
					mjson, _ := json.Marshal(op.matched)
					_, err = tx.Exec(
						"UPDATE packets SET contains_flagid = 1, matched_flagids = ?, flagid_round = ? WHERE id = ?",
						string(mjson), currentRound, op.id,
					)
					total++
				} else {
					_, err = tx.Exec(
						"UPDATE packets SET flagid_round = ? WHERE id = ?",
						currentRound, op.id,
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
	if checker == nil || currentRound == 0 {
		return 0, nil
	}
	fromTS := from.UTC().Format(time.RFC3339Nano)
	toTS := to.UTC().Format(time.RFC3339Nano)

	var total int64
	const batchSize = 500
	const updateChunk = 32

	var lastID int64
	for {
		rows, err := s.db.Query(
			`SELECT id, body, body_string, url, headers
			 FROM packets
			 WHERE id > ? AND timestamp >= ? AND timestamp <= ?
			 ORDER BY id ASC LIMIT ?`,
			lastID, fromTS, toTS, batchSize,
		)
		if err != nil {
			return total, fmt.Errorf("window backfill select: %w", err)
		}

		type pktUpdate struct {
			id      int64
			matched []string
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
				updates = append(updates, pktUpdate{id: id, matched: vals})
			} else {
				markProcessed = append(markProcessed, id)
			}
		}
		rows.Close()

		batchCount := len(updates) + len(markProcessed)
		if batchCount == 0 {
			break
		}

		allOps := make([]pktUpdate, 0, batchCount)
		allOps = append(allOps, updates...)
		for _, id := range markProcessed {
			allOps = append(allOps, pktUpdate{id: id})
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
			for _, op := range allOps[chunkStart:chunkEnd] {
				if op.matched != nil {
					mjson, _ := json.Marshal(op.matched)
					_, err = tx.Exec(
						"UPDATE packets SET contains_flagid = 1, matched_flagids = ?, flagid_round = ? WHERE id = ?",
						string(mjson), currentRound, op.id,
					)
					total++
				} else {
					_, err = tx.Exec(
						"UPDATE packets SET flagid_round = ? WHERE id = ?",
						currentRound, op.id,
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

// Close stops the batched writer (draining any queued packets) and closes the database.
func (s *PacketStore) Close() error {
	close(s.stopCh)
	<-s.doneCh
	s.rdb.Close()
	return s.db.Close()
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

	// Step 2: get all packets in the same session (same TCP connection)
	sessionPackets, err := s.scanPackets(
		"SELECT "+packetSelectCols+" FROM packets WHERE session_id = ? ORDER BY timestamp ASC",
		[]interface{}{startPkt.SessionID},
	)
	if err != nil {
		return nil, err
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
	minTS := minTime.UTC().Format(time.RFC3339Nano)
	maxTS := maxTime.UTC().Format(time.RFC3339Nano)

	// In non-SNAT environments, constrain token correlation to the same peer IP.
	peerIP := startPkt.SrcIP
	if startPkt.Direction == DirectionResponse {
		peerIP = startPkt.DstIP
	}
	peerFilter := !s.looksLikeSNAT(startPkt.ServiceID, sessionPackets[0].Timestamp)

	// Step 4: find all packets containing any of these tokens (scoped to same service)
	sessionIDs := map[string]bool{startPkt.SessionID: true}
	for _, token := range tokens {
		if len(token) < 8 {
			continue // skip very short tokens to avoid false matches
		}
		like := "%" + token + "%"
		query := "SELECT " + packetSelectCols + " FROM packets WHERE service_id = ? AND timestamp BETWEEN ? AND ? AND (headers LIKE ? OR body_string LIKE ?)"
		args := []interface{}{startPkt.ServiceID, minTS, maxTS, like, like}
		if peerFilter && peerIP != "" {
			query += " AND ((direction = 'request' AND src_ip = ?) OR (direction = 'response' AND dst_ip = ?))"
			args = append(args, peerIP, peerIP)
		}
		query += " LIMIT 500"
		rows, err := s.scanPackets(query, args)
		if err != nil {
			continue
		}
		for _, p := range rows {
			sessionIDs[p.SessionID] = true
		}
	}

	// Step 5: fetch all packets from all discovered sessions
	return s.fetchSessions(startPkt.SessionID, sessionIDs, sessionPackets)
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
		minTime.UTC().Format(time.RFC3339Nano),
		maxTime.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return sessionPackets, nil
	}
	defer rows.Close()

	sessionIDs := map[string]bool{startPkt.SessionID: true}
	for rows.Next() {
		var sid string
		if err := rows.Scan(&sid); err == nil {
			sessionIDs[sid] = true
		}
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
	wideMin := around.Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano)
	wideMax := around.Add(2 * time.Minute).UTC().Format(time.RFC3339Nano)

	var distinctIPs int
	err := s.rdb.QueryRow(
		`SELECT COUNT(DISTINCT src_ip) FROM packets
		 WHERE service_id = ? AND direction = 'request'
		 AND timestamp BETWEEN ? AND ?`,
		serviceID, wideMin, wideMax,
	).Scan(&distinctIPs)
	if err != nil {
		return false
	}

	// In SNAT, all traffic comes from 1 gateway IP.
	// In normal environments, multiple attacker IPs are visible.
	return distinctIPs <= 1
}

// fetchSessions returns packets from all discovered sessions, or the original
// sessionPackets if only one session was found.
func (s *PacketStore) fetchSessions(originalSID string, sessionIDs map[string]bool, sessionPackets []*Packet) ([]*Packet, error) {
	if len(sessionIDs) <= 1 {
		return sessionPackets, nil
	}

	var placeholders []string
	var args []interface{}
	for sid := range sessionIDs {
		placeholders = append(placeholders, "?")
		args = append(args, sid)
	}

	query := "SELECT " + packetSelectCols + " FROM packets WHERE session_id IN (" + strings.Join(placeholders, ",") + ") ORDER BY timestamp ASC LIMIT 500"
	return s.scanPackets(query, args)
}

// extractAuthTokens extracts Bearer tokens, session cookies, and JSON token
// fields from packet headers and bodies. These values are used to correlate
// packets across TCP connections that belong to the same logical session.
func extractAuthTokens(packets []*Packet) []string {
	seen := map[string]bool{}
	var tokens []string

	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			tokens = append(tokens, v)
		}
	}

	for _, p := range packets {
		// Check Authorization header (Bearer tokens)
		if auth, ok := p.Headers["Authorization"]; ok {
			add(extractBearerToken(auth))
		}

		// Check Cookie header (requests) — e.g., "session=abc123; csrftoken=xyz"
		if cookie, ok := p.Headers["Cookie"]; ok {
			for _, v := range extractCookieValues(cookie) {
				add(v)
			}
		}

		// Check Set-Cookie header (responses) — e.g., "session=abc123; Path=/; HttpOnly"
		if p.Direction == DirectionResponse {
			if sc, ok := p.Headers["Set-Cookie"]; ok {
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
	if strings.HasPrefix(auth, "Bearer: ") {
		return strings.TrimSpace(auth[8:])
	}
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimSpace(auth[7:])
	}
	return ""
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
	for _, cookie := range strings.Split(header, ",") {
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
				return `%"` + name + `"%`
			}
			return `%"` + name + `"%` + value + `%`
		}
	}
	return "%" + q + "%"
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
		args = append(args, q.TimeFrom.UTC().Format(time.RFC3339Nano))
	}
	if q.TimeTo != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, q.TimeTo.UTC().Format(time.RFC3339Nano))
	}
	if q.URL != "" {
		conditions = append(conditions, "url LIKE ?")
		args = append(args, "%"+q.URL+"%")
	}
	if q.Contains != "" {
		conditions = append(conditions, "(body_string LIKE ? OR headers LIKE ? OR url LIKE ?)")
		like := "%" + q.Contains + "%"
		args = append(args, like, like, like)
	}
	if q.ContainsBody != "" {
		conditions = append(conditions, "body_string LIKE ?")
		args = append(args, "%"+q.ContainsBody+"%")
	}
	if q.ContainsHeaders != "" {
		conditions = append(conditions, "headers LIKE ?")
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
		conditions = append(conditions, "url NOT LIKE ?")
		args = append(args, "%"+q.NotURL+"%")
	}
	if q.NotContains != "" {
		conditions = append(conditions, "NOT (body_string LIKE ? OR headers LIKE ? OR url LIKE ?)")
		like := "%" + q.NotContains + "%"
		args = append(args, like, like, like)
	}
	if q.NotContainsBody != "" {
		conditions = append(conditions, "body_string NOT LIKE ?")
		args = append(args, "%"+q.NotContainsBody+"%")
	}
	if q.NotContainsHeaders != "" {
		conditions = append(conditions, "headers NOT LIKE ?")
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
	if q.HasMatchedRules != nil {
		if *q.HasMatchedRules {
			conditions = append(conditions, "matched_rules != '[]'")
		} else {
			conditions = append(conditions, "matched_rules = '[]'")
		}
	}
	if q.Dropped != nil && *q.Dropped {
		// Fast path: indexed column computed at ingestion time.
		conditions = append(conditions, "has_drop_match = 1")
	}
	if q.HiddenBefore != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, q.HiddenBefore.UTC().Format(time.RFC3339Nano))
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
