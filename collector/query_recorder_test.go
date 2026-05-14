// Copyright 2018 The Prometheus Authors, 2026 Percona LLC
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build integration

package collector

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"slices"
	"sync"
	"testing"

	"github.com/go-sql-driver/mysql"
)

var (
	_ driver.Connector      = (*recordingConnector)(nil)
	_ driver.Conn           = (*recordingConn)(nil)
	_ driver.QueryerContext = (*recordingConn)(nil)
	_ driver.Pinger         = (*recordingConn)(nil)
)

// queryRecorder collects every SQL string issued via QueryContext on the wrapped
// connection. The string is recorded before delegation, so attempts that fail or
// return driver.ErrSkip are still captured.
type queryRecorder struct {
	mu      sync.Mutex
	queries []string
}

func (r *queryRecorder) record(q string) {
	r.mu.Lock()
	r.queries = append(r.queries, q)
	r.mu.Unlock()
}

func (r *queryRecorder) recordedQueries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.queries)
}

// recordingConnector wraps a driver.Connector and returns connections that
// record every QueryContext call. Integration tests use this to assert which
// SQL the collector issued against a real database without having to mock the
// database itself.
type recordingConnector struct {
	inner    driver.Connector
	recorder *queryRecorder
}

func (c *recordingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &recordingConn{inner: conn, recorder: c.recorder}, nil
}

func (c *recordingConnector) Driver() driver.Driver { return c.inner.Driver() }

type recordingConn struct {
	inner    driver.Conn
	recorder *queryRecorder
}

func (c *recordingConn) Prepare(query string) (driver.Stmt, error) {
	return c.inner.Prepare(query)
}

func (c *recordingConn) Close() error { return c.inner.Close() }

func (c *recordingConn) Begin() (driver.Tx, error) { return c.inner.Begin() }

func (c *recordingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.recorder.record(query)
	if qc, ok := c.inner.(driver.QueryerContext); ok {
		return qc.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *recordingConn) Ping(ctx context.Context) error {
	if p, ok := c.inner.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return driver.ErrSkip
}

// openRecordingDB opens a *sql.DB against dsn whose connections record every
// QueryContext SQL string into the returned recorder. Inspect captures via
// (*queryRecorder).recordedQueries.
func openRecordingDB(t *testing.T, dsn string) (*sql.DB, *queryRecorder) {
	t.Helper()
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	inner, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatalf("mysql.NewConnector: %v", err)
	}
	rec := &queryRecorder{}
	db := sql.OpenDB(&recordingConnector{
		inner:    inner,
		recorder: rec,
	})
	return db, rec
}
