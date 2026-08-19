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

package collector

import (
	"database/sql"
	"fmt"
	"math"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

// TestScrapeAutoIncrementColumnsMaxValue evaluates the max_int expression on the
// server started by docker-compose, so every flavor of the CI matrix checks it.
// ZEROFILL appends another attribute after "unsigned" in column_type, which an
// anchored LIKE '% unsigned' misses: such columns reported the signed maximum
// and so looked twice as full as they were.
func TestScrapeAutoIncrementColumnsMaxValue(t *testing.T) {
	if testing.Short() {
		t.Skip("-short is passed, skipping test")
	}

	db, err := sql.Open("mysql", "root@tcp(127.0.0.1:3306)/")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const dbName = "test_auto_increment_db"

	if _, err := db.Exec("CREATE DATABASE IF NOT EXISTS " + dbName); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.Exec("DROP DATABASE " + dbName); err != nil {
			t.Fatal(err)
		}
	}()

	cases := []struct {
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

	for _, c := range cases {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE TABLE %s.%s (id %s, PRIMARY KEY (id))", dbName, c.name, c.column)); err != nil {
			t.Fatalf("creating table %s: %v", c.name, err)
		}

		// The scraper skips tables whose information_schema.tables.auto_increment
		// is NULL, which is what a never-used counter reports. ANALYZE TABLE then
		// refreshes the value the dictionary cache would otherwise serve for
		// information_schema_stats_expiry seconds.
		if _, err := db.ExecContext(ctx, fmt.Sprintf("INSERT INTO %s.%s () VALUES ()", dbName, c.name)); err != nil {
			t.Fatalf("seeding table %s: %v", c.name, err)
		}
		if _, err := db.ExecContext(ctx, fmt.Sprintf("ANALYZE TABLE %s.%s", dbName, c.name)); err != nil {
			t.Fatalf("analyzing table %s: %v", c.name, err)
		}
	}

	ch := make(chan prometheus.Metric)
	scrapeErr := make(chan error, 1)
	go func() {
		scrapeErr <- (ScrapeAutoIncrementColumns{}).Scrape(ctx, &instance{db: db}, ch, promslog.NewNopLogger())
		close(ch)
	}()

	got := make(map[string]float64)
	for metric := range ch {
		if metric.Desc() != globalInfoSchemaAutoIncrementMaxDesc {
			continue
		}
		result := readMetric(metric)
		if result.labels["schema"] != dbName {
			continue
		}
		got[result.labels["table"]] = result.value
	}
	if err := <-scrapeErr; err != nil {
		t.Fatalf("scrape failed: %v", err)
	}

	for _, c := range cases {
		gotMax, ok := got[c.name]
		if !ok {
			t.Errorf("no max metric for table %s; collected: %v", c.name, got)
			continue
		}
		if gotMax != c.wantMax {
			t.Errorf("table %s (%s): max = %.0f, want %.0f", c.name, c.column, gotMax, c.wantMax)
		}
	}
}
