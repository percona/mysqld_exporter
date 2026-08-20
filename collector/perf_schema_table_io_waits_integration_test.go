// Copyright 2026 Percona LLC
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
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/testcontainers/testcontainers-go"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"
)

func TestScrapePerfTableIOWaitsMySQLCompatibility(t *testing.T) {
	cases := []struct {
		name  string
		image string
	}{
		{"MySQL 8.0", "mysql:8.0"},
		{"MySQL 9.7", "mysql:9.7"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			dsn := startPerfTableIOContainer(t, ctx, tc.image)

			instance, err := newInstance(ctx, dsn)
			if err != nil {
				t.Fatalf("creating instance: %v", err)
			}
			t.Cleanup(func() { _ = instance.Close() })
			db := instance.getDB()

			if _, err := db.ExecContext(ctx, "CREATE TABLE table_activity (id INT PRIMARY KEY, value INT)"); err != nil {
				t.Fatalf("creating test table: %v", err)
			}
			if _, err := db.ExecContext(ctx, "INSERT INTO table_activity VALUES (1, 1), (2, 2)"); err != nil {
				t.Fatalf("inserting test rows: %v", err)
			}
			rows, err := db.QueryContext(ctx, "SELECT * FROM table_activity")
			if err != nil {
				t.Fatalf("reading test rows: %v", err)
			}
			for rows.Next() {
				var id, value int
				if err := rows.Scan(&id, &value); err != nil {
					_ = rows.Close()
					t.Fatalf("scanning test rows: %v", err)
				}
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				t.Fatalf("iterating test rows: %v", err)
			}
			if err := rows.Close(); err != nil {
				t.Fatalf("closing test rows: %v", err)
			}
			if _, err := db.ExecContext(ctx, "UPDATE table_activity SET value = value + 1 WHERE id = 1"); err != nil {
				t.Fatalf("updating test row: %v", err)
			}
			if _, err := db.ExecContext(ctx, "DELETE FROM table_activity WHERE id = 2"); err != nil {
				t.Fatalf("deleting test row: %v", err)
			}

			metrics := gatherPerfTableIOWaitMetrics(t, ctx, dsn)
			assertTableOperationCounter(t, metrics, "test", "table_activity", "fetch")
			assertTableOperationCounter(t, metrics, "test", "table_activity", "insert")
			assertTableOperationCounter(t, metrics, "test", "table_activity", "update")
			assertTableOperationCounter(t, metrics, "test", "table_activity", "delete")
		})
	}
}

func startPerfTableIOContainer(t *testing.T, ctx context.Context, image string) string {
	t.Helper()

	// MySQL 9.7 autosizes InnoDB from host memory and gets OOM killed on a
	// Docker VM that is already busy, where 8.0 still fits. The counters under
	// test do not depend on either size, so pin them low enough that the test
	// runs on a developer machine as well as in CI. innodb_redo_log_capacity
	// only exists on 8.0.30 and newer, so keep it off the 8.0 line: pinning
	// that entry to an older patch release would fail to start on an unknown
	// variable rather than skip the flag.
	args := []string{
		"--performance-schema=ON",
		"--innodb-buffer-pool-size=64M",
	}
	if !strings.HasPrefix(image, "mysql:8.0") {
		args = append(args, "--innodb-redo-log-capacity=16M")
	}

	container, err := tcmysql.Run(ctx, image,
		tcmysql.WithDatabase("test"),
		tcmysql.WithUsername("root"),
		tcmysql.WithPassword("test"),
		testcontainers.WithCmdArgs(args...),
	)
	if err != nil {
		t.Fatalf("starting %s: %v", image, err)
	}
	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	dsn, err := container.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("getting %s connection string: %v", image, err)
	}
	return dsn
}

func gatherPerfTableIOWaitMetrics(
	t *testing.T,
	ctx context.Context,
	dsn string,
) []*dto.Metric {
	t.Helper()

	registry := prometheus.NewRegistry()
	registry.MustRegister(New(ctx, dsn, []Scraper{ScrapePerfTableIOWaits{}}, promslog.NewNopLogger()))
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gathering exporter metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() == "mysql_perf_schema_table_io_waits_total" {
			return family.Metric
		}
	}

	t.Fatal("mysql_perf_schema_table_io_waits_total metric family was not exported")
	return nil
}

func assertTableOperationCounter(
	t *testing.T,
	metrics []*dto.Metric,
	schema, table, operation string,
) {
	t.Helper()

	for _, metric := range metrics {
		labels := make(map[string]string, len(metric.Label))
		for _, pair := range metric.Label {
			labels[pair.GetName()] = pair.GetValue()
		}
		if labels["schema"] == schema &&
			labels["name"] == table &&
			labels["operation"] == operation &&
			metric.GetCounter().GetValue() > 0 {
			return
		}
	}

	t.Errorf("missing positive table I/O counter for %s.%s operation %s", schema, table, operation)
}
