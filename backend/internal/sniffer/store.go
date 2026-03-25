package sniffer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
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
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			service_id TEXT    NOT NULL,
			timestamp  TEXT    NOT NULL,
			src_ip     TEXT    NOT NULL,
			src_port   INTEGER NOT NULL,
			dst_ip     TEXT    NOT NULL,
			dst_port   INTEGER NOT NULL,
			protocol   TEXT    NOT NULL,
			direction  TEXT    NOT NULL,
			method     TEXT    NOT NULL DEFAULT '',
			url        TEXT    NOT NULL DEFAULT '',
			status     INTEGER NOT NULL DEFAULT 0,
			headers    TEXT    NOT NULL DEFAULT '{}',
			body       BLOB,
			body_string TEXT   NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_packets_service_id ON packets(service_id);
		CREATE INDEX IF NOT EXISTS idx_packets_timestamp  ON packets(timestamp);
	`)
	return err
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

	res, err := s.db.Exec(`
		INSERT INTO packets (service_id, timestamp, src_ip, src_port, dst_ip, dst_port,
			protocol, direction, method, url, status, headers, body, body_string)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ServiceID,
		p.Timestamp.UTC().Format(time.RFC3339Nano),
		p.SrcIP, p.SrcPort,
		p.DstIP, p.DstPort,
		p.Protocol, p.Direction,
		p.Method, p.URL, p.Status,
		string(headersJSON),
		p.Body, p.BodyString,
	)
	if err != nil {
		return fmt.Errorf("inserting packet: %w", err)
	}

	id, _ := res.LastInsertId()
	p.ID = id
	return nil
}

// Query retrieves packets matching the given filters.
func (s *PacketStore) Query(q PacketQuery) ([]*Packet, int, error) {
	where, args := buildWhere(q)

	// Get total count
	var total int
	countSQL := "SELECT COUNT(*) FROM packets" + where
	if err := s.db.QueryRow(countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting packets: %w", err)
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

	querySQL := "SELECT id, service_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, direction, method, url, status, headers, body, body_string FROM packets" +
		where + " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := s.db.Query(querySQL, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying packets: %w", err)
	}
	defer rows.Close()

	var packets []*Packet
	for rows.Next() {
		p := &Packet{}
		var ts string
		var headersJSON string
		if err := rows.Scan(
			&p.ID, &p.ServiceID, &ts,
			&p.SrcIP, &p.SrcPort, &p.DstIP, &p.DstPort,
			&p.Protocol, &p.Direction,
			&p.Method, &p.URL, &p.Status,
			&headersJSON, &p.Body, &p.BodyString,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning packet: %w", err)
		}

		p.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)

		if headersJSON != "" && headersJSON != "{}" {
			json.Unmarshal([]byte(headersJSON), &p.Headers)
		}

		packets = append(packets, p)
	}

	return packets, total, rows.Err()
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
	if q.TimeFrom != nil {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, q.TimeFrom.UTC().Format(time.RFC3339Nano))
	}
	if q.TimeTo != nil {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, q.TimeTo.UTC().Format(time.RFC3339Nano))
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}
