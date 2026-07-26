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
	"fmt"
	"math"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

// TestScrapeAutoIncrementColumnsMaxValue evaluates the max_int expression on a
// real server. ZEROFILL appends another attribute after "unsigned" in
// column_type, which an anchored LIKE '% unsigned' misses, so those columns used
// to report the signed maximum and looked twice as full as they were.
func TestScrapeAutoIncrementColumnsMaxValue(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration test in -short mode")
	}
	if _, err := kingpin.CommandLine.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	tables := []struct {
		name    string
		column  string
		wantMax float64
	}{
		{"signed_int", "int not null auto_increment", math.Pow(2, 31) - 1},
		{"unsigned_int", "int unsigned not null auto_increment", math.Pow(2, 32) - 1},
		{"zerofill_int", "int unsigned zerofill not null auto_increment", math.Pow(2, 32) - 1},
		{"unsigned_smallint", "smallint unsigned not null auto_increment", math.Pow(2, 16) - 1},
		{"unsigned_bigint", "bigint unsigned not null auto_increment", math.Pow(2, 64) - 1},
	}

	ctx := t.Context()
	// ZEROFILL is deprecated since 8.0.17, so pin a version that still accepts it.
	dsn := startContainerForCase(t, ctx, "mysql:8.0", true)

	db, _ := openRecordingDB(t, dsn)
	t.Cleanup(func() { _ = db.Close() })

	for _, table := range tables {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE TABLE %s (id %s, PRIMARY KEY (id))", table.name, table.column)); err != nil {
			t.Fatalf("creating table %s: %v", table.name, err)
		}
		// The scraper skips tables whose information_schema.tables.auto_increment
		// is NULL, which is what a never-used counter reports. ANALYZE TABLE then
		// refreshes the value the dictionary cache would otherwise serve for
		// information_schema_stats_expiry seconds.
		if _, err := db.ExecContext(ctx, fmt.Sprintf("INSERT INTO %s () VALUES ()", table.name)); err != nil {
			t.Fatalf("seeding table %s: %v", table.name, err)
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ANALYZE TABLE %s", table.name)); err != nil {
			t.Fatalf("analyzing table %s: %v", table.name, err)
		}
	}

	instance, err := newInstanceFromDB(ctx, db)
	if err != nil {
		t.Fatalf("failed to create new instance: %v", err)
	}

	ch := make(chan prometheus.Metric)
	scrapeErr := make(chan error, 1)
	go func() {
		scrapeErr <- (ScrapeAutoIncrementColumns{}).Scrape(ctx, instance, ch, promslog.NewNopLogger())
		close(ch)
	}()

	got := make(map[string]float64)
	for metric := range ch {
		if metric.Desc() != globalInfoSchemaAutoIncrementMaxDesc {
			continue
		}
		result := readMetric(metric)
		if result.labels["schema"] != "test" {
			continue
		}
		got[result.labels["table"]] = result.value
	}
	if err := <-scrapeErr; err != nil {
		t.Fatalf("scrape failed: %v", err)
	}

	for _, table := range tables {
		gotMax, ok := got[table.name]
		if !ok {
			t.Errorf("no max metric for table %s; collected: %v", table.name, got)
			continue
		}
		if gotMax != table.wantMax {
			t.Errorf("table %s (%s): max = %.0f, want %.0f", table.name, table.column, gotMax, table.wantMax)
		}
	}
}
