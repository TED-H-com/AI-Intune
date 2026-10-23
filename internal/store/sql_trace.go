package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"net/url"
	"time"
)

// TraceSQL installs an opt-in diagnostic observer. Call only on an idle Store,
// before serving requests. It observes SQL text and bind values; callers must
// use synthetic data or redact values before logging. Duration includes row
// iteration and Close, rather than just preparing the statement.
func (s *Store) TraceSQL(observe func(string, []any, time.Duration)) error {
	var seq int
	var name, path string
	rows, err := s.rdb.Query("PRAGMA database_list")
	if err != nil {
		return err
	}
	for rows.Next() {
		if err = rows.Scan(&seq, &name, &path); err != nil {
			break
		}
		if name == "main" {
			break
		}
	}
	rows.Close()
	if err != nil {
		return err
	}
	pools := []**sql.DB{&s.db, &s.rdb}
	for i, target := range pools {
		old := *target
		u := &url.URL{Scheme: "file", Path: path}
		q := u.Query()
		for _, p := range []string{"foreign_keys(ON)", "busy_timeout(10000)", "synchronous(NORMAL)"} {
			q.Add("_pragma", p)
		}
		if i == 0 {
			q.Set("_txlock", "immediate")
		} else {
			q.Add("_pragma", "query_only(1)")
		}
		u.RawQuery = q.Encode()
		pool := sql.OpenDB(&traceConnector{d: old.Driver(), dsn: u.String(), observe: observe})
		if i == 0 {
			pool.SetMaxOpenConns(1)
			pool.SetMaxIdleConns(1)
		} else {
			pool.SetMaxOpenConns(8)
		}
		if err := pool.Ping(); err != nil {
			pool.Close()
			return err
		}
		*target = pool
		old.Close()
	}
	return nil
}

type traceConnector struct {
	d       driver.Driver
	dsn     string
	observe func(string, []any, time.Duration)
}

func (c *traceConnector) Driver() driver.Driver { return c.d }
func (c *traceConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.d.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &traceConn{Conn: conn, observe: c.observe}, nil
}

type traceConn struct {
	driver.Conn
	observe func(string, []any, time.Duration)
}

func traceArgs(v []driver.NamedValue) []any {
	out := make([]any, len(v))
	for i, a := range v {
		out[i] = a.Value
	}
	return out
}
func (c *traceConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	start := time.Now()
	rows, err := c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
	done := func() { c.observe(q, traceArgs(args), time.Since(start)) }
	if err != nil {
		done()
		return nil, err
	}
	return &traceRows{Rows: rows, done: done}, nil
}
func (c *traceConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	start := time.Now()
	result, err := c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
	c.observe(q, traceArgs(args), time.Since(start))
	return result, err
}
func (c *traceConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
}

type traceRows struct {
	driver.Rows
	done func()
}

func (r *traceRows) finish() {
	if r.done != nil {
		r.done()
		r.done = nil
	}
}
func (r *traceRows) Close() error { err := r.Rows.Close(); r.finish(); return err }
func (r *traceRows) Next(v []driver.Value) error {
	err := r.Rows.Next(v)
	if err == io.EOF {
		r.finish()
	}
	return err
}
