package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/dnstrike/dnstrike/pkg/models"
)

var ErrNotFound = errors.New("kayıt bulunamadı")

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("sqlite açma: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
	PRAGMA journal_mode=WAL;
	PRAGMA foreign_keys=ON;
	CREATE TABLE IF NOT EXISTS targets (
	 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, ip_address TEXT NOT NULL,
	 port INTEGER NOT NULL, description TEXT NOT NULL DEFAULT '', environment TEXT NOT NULL DEFAULT '',
	 udp_enabled INTEGER NOT NULL DEFAULT 1, tcp_enabled INTEGER NOT NULL DEFAULT 1,
	 tags_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
	 UNIQUE(ip_address, port));
	CREATE TABLE IF NOT EXISTS tests (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL, scenario TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT, duration INTEGER NOT NULL DEFAULT 0, config_json TEXT NOT NULL DEFAULT '{}', resilience_score REAL, FOREIGN KEY(target_id) REFERENCES targets(id));
	CREATE TABLE IF NOT EXISTS test_results (id INTEGER PRIMARY KEY AUTOINCREMENT, test_id INTEGER NOT NULL, result_json TEXT NOT NULL, FOREIGN KEY(test_id) REFERENCES tests(id));
	CREATE TABLE IF NOT EXISTS metrics (id INTEGER PRIMARY KEY AUTOINCREMENT, test_id INTEGER NOT NULL, timestamp TEXT NOT NULL, data_json TEXT NOT NULL, FOREIGN KEY(test_id) REFERENCES tests(id));
	CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, test_id INTEGER NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL, evidence TEXT NOT NULL, recommendation TEXT NOT NULL, FOREIGN KEY(test_id) REFERENCES tests(id));
	CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, test_id INTEGER NOT NULL, format TEXT NOT NULL, path TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(test_id) REFERENCES tests(id));
	CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, config_json TEXT NOT NULL, created_at TEXT NOT NULL);
	CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, updated_at TEXT NOT NULL);`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("şema oluşturma: %w", err)
	}
	if err := s.ensureColumn(ctx, "tests", "created_at", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "tests", "result_summary_json", "TEXT NOT NULL DEFAULT '{}'"); err != nil {
		return err
	}
	return nil
}

func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return fmt.Errorf("şema inceleme: %w", err)
	}
	found := false
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			_ = rows.Close()
			return fmt.Errorf("şema inceleme: %w", err)
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	if _, err := s.db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+definition); err != nil {
		return fmt.Errorf("şema güncelleme: %w", err)
	}
	return nil
}

func (s *Store) CreateTarget(ctx context.Context, t *models.Target) error {
	now := time.Now().UTC()
	tags, _ := json.Marshal(t.Tags)
	r, err := s.db.ExecContext(ctx, `INSERT INTO targets(name,ip_address,port,description,environment,udp_enabled,tcp_enabled,tags_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, t.Name, t.IPAddress, t.Port, t.Description, t.Environment, t.UDPEnabled, t.TCPEnabled, string(tags), now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("target kaydetme: %w", err)
	}
	t.ID, err = r.LastInsertId()
	t.CreatedAt = now
	t.UpdatedAt = now
	return err
}

func (s *Store) ListTargets(ctx context.Context) ([]models.Target, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,ip_address,port,description,environment,udp_enabled,tcp_enabled,tags_json,created_at,updated_at FROM targets ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]models.Target, 0)
	for rows.Next() {
		t, err := scanTarget(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, t)
	}
	return items, rows.Err()
}

func (s *Store) GetTarget(ctx context.Context, id int64) (models.Target, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,ip_address,port,description,environment,udp_enabled,tcp_enabled,tags_json,created_at,updated_at FROM targets WHERE id=?`, id)
	t, err := scanTarget(row)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func (s *Store) DeleteTarget(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, "SELECT id FROM tests WHERE target_id=?", id)
	if err == nil {
		var testIDs []string
		for rows.Next() {
			var tid int
			if err := rows.Scan(&tid); err == nil {
				testIDs = append(testIDs, fmt.Sprintf("%d", tid))
			}
		}
		rows.Close()
		if len(testIDs) > 0 {
			inClause := strings.Join(testIDs, ",")
			if _, err := tx.ExecContext(ctx, "DELETE FROM test_results WHERE test_id IN ("+inClause+")"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM metrics WHERE test_id IN ("+inClause+")"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM findings WHERE test_id IN ("+inClause+")"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM reports WHERE test_id IN ("+inClause+")"); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "DELETE FROM tests WHERE target_id=?", id); err != nil {
				return err
			}
		}
	}

	r, err := tx.ExecContext(ctx, `DELETE FROM targets WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

type scanner interface{ Scan(...any) error }

func scanTarget(s scanner) (models.Target, error) {
	var t models.Target
	var tags, created, updated string
	err := s.Scan(&t.ID, &t.Name, &t.IPAddress, &t.Port, &t.Description, &t.Environment, &t.UDPEnabled, &t.TCPEnabled, &tags, &created, &updated)
	if err != nil {
		return t, err
	}
	_ = json.Unmarshal([]byte(tags), &t.Tags)
	t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	t.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return t, nil
}

func (s *Store) CreateTest(ctx context.Context, test *models.Test) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `INSERT INTO tests(target_id,scenario,status,created_at,duration,config_json) VALUES(?,?,?,?,?,?)`,
		test.TargetID, test.Scenario, test.Status, now.Format(time.RFC3339Nano), test.DurationSeconds, string(test.Config))
	if err != nil {
		return fmt.Errorf("test kaydetme: %w", err)
	}
	test.ID, err = result.LastInsertId()
	test.CreatedAt = now
	return err
}

func (s *Store) ListTests(ctx context.Context, filter models.TestFilter) ([]models.Test, error) {
	query := strings.Builder{}
	query.WriteString(`SELECT id,target_id,scenario,status,created_at,started_at,finished_at,duration,config_json,resilience_score,result_summary_json FROM tests WHERE 1=1`)
	args := make([]any, 0, 4)
	if filter.TargetID > 0 {
		query.WriteString(" AND target_id=?")
		args = append(args, filter.TargetID)
	}
	if filter.Scenario != "" {
		query.WriteString(" AND scenario=?")
		args = append(args, filter.Scenario)
	}
	if filter.Status != "" {
		query.WriteString(" AND status=?")
		args = append(args, filter.Status)
	}
	query.WriteString(" ORDER BY id DESC LIMIT ?")
	limit := filter.Limit
	if limit < 1 || limit > 500 {
		limit = 100
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]models.Test, 0)
	for rows.Next() {
		item, err := scanTest(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) GetTest(ctx context.Context, id int64) (models.Test, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,target_id,scenario,status,created_at,started_at,finished_at,duration,config_json,resilience_score,result_summary_json FROM tests WHERE id=?`, id)
	test, err := scanTest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return test, ErrNotFound
	}
	return test, err
}

func (s *Store) TransitionTest(ctx context.Context, id int64, from, to models.TestStatus, at time.Time) error {
	var result sql.Result
	var err error
	switch to {
	case models.TestRunning:
		result, err = s.db.ExecContext(ctx, `UPDATE tests SET status=?,started_at=? WHERE id=? AND status=?`, to, at.UTC().Format(time.RFC3339Nano), id, from)
	case models.TestCompleted, models.TestFailed, models.TestCancelled:
		result, err = s.db.ExecContext(ctx, `UPDATE tests SET status=?,finished_at=?,duration=CASE WHEN started_at IS NULL OR started_at='' THEN duration ELSE CAST(strftime('%s',?)-strftime('%s',started_at) AS INTEGER) END WHERE id=? AND status=?`, to, at.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano), id, from)
	default:
		return errors.New("desteklenmeyen test durumu")
	}
	if err != nil {
		return fmt.Errorf("test durumu güncelleme: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) UpdateTestResult(ctx context.Context, id int64, score int, result json.RawMessage) error {
	_, err := s.db.ExecContext(ctx, "UPDATE tests SET resilience_score=?, result_summary_json=? WHERE id=?", score, string(result), id)
	return err
}

func (s *Store) DeleteTest(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete associated records first
	if _, err := tx.ExecContext(ctx, "DELETE FROM test_results WHERE test_id=?", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM metrics WHERE test_id=?", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM findings WHERE test_id=?", id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM reports WHERE test_id=?", id); err != nil {
		return err
	}

	// Delete test
	result, err := tx.ExecContext(ctx, "DELETE FROM tests WHERE id=?", id)
	if err != nil {
		return err
	}
	
	count, _ := result.RowsAffected()
	if count == 0 {
		return ErrNotFound
	}
	
	return tx.Commit()
}

func scanTest(s scanner) (models.Test, error) {
	var test models.Test
	var status, created, config, result string
	var started, finished sql.NullString
	var score sql.NullFloat64
	if err := s.Scan(&test.ID, &test.TargetID, &test.Scenario, &status, &created, &started, &finished, &test.DurationSeconds, &config, &score, &result); err != nil {
		return test, err
	}
	test.Status = models.TestStatus(status)
	test.Config = json.RawMessage(config)
	if result != "" && result != "{}" {
		test.Result = json.RawMessage(result)
	}
	test.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if started.Valid && started.String != "" {
		value, err := time.Parse(time.RFC3339Nano, started.String)
		if err != nil {
			return test, fmt.Errorf("test başlangıç zamanı: %w", err)
		}
		test.StartedAt = &value
	}
	if finished.Valid && finished.String != "" {
		value, err := time.Parse(time.RFC3339Nano, finished.String)
		if err != nil {
			return test, fmt.Errorf("test bitiş zamanı: %w", err)
		}
		test.FinishedAt = &value
	}
	if score.Valid {
		test.ResilienceScore = &score.Float64
	}
	return test, nil
}
