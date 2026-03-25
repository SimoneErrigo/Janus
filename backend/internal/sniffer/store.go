package sniffer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

// PacketStore handles SQLite persistence for captured packets.
type PacketStore struct {
	db *sql.DB
}

// NewPacketStore opens (or creates) the SQLite database at dataDir/packets.db.
func NewPacketStore(dataDir string) (*PacketStore, error) {
	dbPath := filepath.Join(dataDir, "packets.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating sqlite: %w", err)
	}

	return &PacketStore{db: db}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS packets (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id    TEXT    NOT NULL,
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
			matched_rules TEXT    NOT NULL DEFAULT '[]',
			flagged       INTEGER NOT NULL DEFAULT 0
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
	} {
		db.Exec(col) // ignore "duplicate column" errors
	}

	return nil
}

// Insert stores a packet in the database.
func (s *PacketStore) Insert(p *Packet) error {
	// Auto-fill body_string if body is valid UTF-8
	if len(p.Body) > 0 && p.BodyString == "" && utf8.Valid(p.Body) {
		p.BodyString = string(p.Body)
	}

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

	res, err := s.db.Exec(`
		INSERT INTO packets (service_id, timestamp, src_ip, src_port, dst_ip, dst_port,
			protocol, direction, method, url, status, headers, body, body_string,
			matched_rules, flagged)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ServiceID,
		p.Timestamp.UTC().Format(time.RFC3339Nano),
		p.SrcIP, p.SrcPort,
		p.DstIP, p.DstPort,
		p.Protocol, p.Direction,
		p.Method, p.URL, p.Status,
		string(headersJSON),
		p.Body, p.BodyString,
		string(matchedRulesJSON), flaggedInt,
	)
	if err != nil {
		return fmt.Errorf("inserting packet: %w", err)
	}

	id, _ := res.LastInsertId()
	p.ID = id
	return nil
}

// Query retrieves packets matching the given filters.
// The regex filter is applied in Go after the SQL query for correct pagination.
func (s *PacketStore) Query(q PacketQuery) ([]*Packet, int, error) {
	where, args := buildWhere(q)
	hasRegex := q.Regex != ""

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

	selectCols := "id, service_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, direction, method, url, status, headers, body, body_string, matched_rules, flagged"

	if hasRegex {
		// With regex: fetch all SQL-matching rows, filter in Go, then paginate
		return s.queryWithRegex(q, where, args, selectCols, sortOrder, limit, offset)
	}

	// Without regex: standard SQL pagination
	var total int
	countSQL := "SELECT COUNT(*) FROM packets" + where
	if err := s.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting packets: %w", err)
	}

	querySQL := "SELECT " + selectCols + " FROM packets" +
		where + " ORDER BY timestamp " + sortOrder + " LIMIT ? OFFSET ?"
	queryArgs := append(args, limit, offset)

	packets, err := s.scanPackets(querySQL, queryArgs)
	if err != nil {
		return nil, 0, err
	}

	return packets, total, nil
}

// queryWithRegex fetches SQL-filtered rows, applies regex in Go, then paginates.
func (s *PacketStore) queryWithRegex(q PacketQuery, where string, args []interface{}, selectCols, sortOrder string, limit, offset int) ([]*Packet, int, error) {
	re, err := regexp.Compile(q.Regex)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid regex: %w", err)
	}

	querySQL := "SELECT " + selectCols + " FROM packets" +
		where + " ORDER BY timestamp " + sortOrder

	allPackets, err := s.scanPackets(querySQL, args)
	if err != nil {
		return nil, 0, err
	}

	// Apply regex filter
	var filtered []*Packet
	for _, p := range allPackets {
		if regexMatchesPacket(re, p) {
			filtered = append(filtered, p)
		}
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
		if re.MatchString(k+": "+v) {
			return true
		}
	}
	return false
}

func (s *PacketStore) scanPackets(querySQL string, args []interface{}) ([]*Packet, error) {
	rows, err := s.db.Query(querySQL, args...)
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
		var flaggedInt int
		if err := rows.Scan(
			&p.ID, &p.ServiceID, &ts,
			&p.SrcIP, &p.SrcPort, &p.DstIP, &p.DstPort,
			&p.Protocol, &p.Direction,
			&p.Method, &p.URL, &p.Status,
			&headersJSON, &p.Body, &p.BodyString,
			&matchedRulesJSON, &flaggedInt,
		); err != nil {
			return nil, fmt.Errorf("scanning packet: %w", err)
		}

		p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		p.Flagged = flaggedInt != 0

		if headersJSON != "" && headersJSON != "{}" {
			json.Unmarshal([]byte(headersJSON), &p.Headers)
		}

		if matchedRulesJSON != "" && matchedRulesJSON != "[]" {
			json.Unmarshal([]byte(matchedRulesJSON), &p.MatchedRules)
		}

		if p.MatchedRules == nil {
			p.MatchedRules = []MatchedRuleInfo{}
		}

		packets = append(packets, p)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return packets, nil
}

// Close closes the database.
func (s *PacketStore) Close() error {
	return s.db.Close()
}

func buildWhere(q PacketQuery) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if q.ServiceID != "" {
		conditions = append(conditions, "service_id = ?")
		args = append(args, q.ServiceID)
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
	if q.TimeFrom != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, q.TimeFrom.UTC().Format(time.RFC3339Nano))
	}
	if q.TimeTo != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, q.TimeTo.UTC().Format(time.RFC3339Nano))
	}
	if q.Contains != "" {
		conditions = append(conditions, "(body_string LIKE ? OR headers LIKE ? OR url LIKE ?)")
		like := "%" + q.Contains + "%"
		args = append(args, like, like, like)
	}
	if q.Flagged != nil {
		if *q.Flagged {
			conditions = append(conditions, "flagged = 1")
		} else {
			conditions = append(conditions, "flagged = 0")
		}
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}
