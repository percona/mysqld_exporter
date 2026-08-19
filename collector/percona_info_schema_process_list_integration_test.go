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
	"fmt"
	"strings"
	"testing"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/testcontainers/testcontainers-go"
	tcmariadb "github.com/testcontainers/testcontainers-go/modules/mariadb"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"
)

func TestPScrapeProcesslist(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers integration test in -short mode")
	}
	if _, err := kingpin.CommandLine.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name           string
		image          string
		psEnabled      bool
		expectedSchema string
	}{

		{"MySQL 5.7.39 + PS on -> perf_schema", "mysql:5.7.39", true, processlistPerfSchema},
		{"MySQL 5.7.39 + PS off -> info_schema", "mysql:5.7.39", false, processlistInfoSchema},
		{"MySQL 5.7.38 + PS on -> info_schema", "mysql:5.7.38", true, processlistInfoSchema},
		{"MySQL 5.7.38 + PS off -> info_schema", "mysql:5.7.38", false, processlistInfoSchema},
		{"MariaDB 10.11 + PS on -> info_schema", "mariadb:10.11", true, processlistInfoSchema},
		{"MariaDB 10.11 + PS off -> info_schema", "mariadb:10.11", false, processlistInfoSchema},

		// Forward-compatibility coverage
		{"MySQL >=8 PS on -> perf_schema", "mysql:8", true, processlistPerfSchema},
		{"MySQL >=9 PS on -> perf_schema", "mysql:9", true, processlistPerfSchema},
		{"MySQL latest PS on -> perf_schema", "mysql:latest", true, processlistPerfSchema},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			dsn := startContainerForCase(t, ctx, tc.image, tc.psEnabled)

			db, rec := openRecordingDB(t, dsn)
			t.Cleanup(func() { _ = db.Close() })

			instance, err := newInstanceFromDB(ctx, db)

			if err != nil {
				t.Fatalf("failed to create new instance: %v", err)
			}

			ch := make(chan prometheus.Metric)
			defer close(ch)
			go func() {
				for range ch {
				}
			}()

			if err := (PScrapeProcesslist{}).Scrape(ctx, instance, ch, promslog.NewNopLogger()); err != nil {
				t.Fatalf("scrape failed: %v; recorded queries: %v", err, rec.recordedQueries())
			}

			wantFragment := fmt.Sprintf("FROM %s.processlist", tc.expectedSchema)
			queries := rec.recordedQueries()
			for _, q := range queries {
				if strings.Contains(strings.Join(strings.Fields(q), " "), wantFragment) {
					return
				}
			}
			t.Fatalf("expected a query against %s; got: %v", tc.expectedSchema, queries)
		})
	}
}

// startContainerForCase boots a MySQL or MariaDB container with specified configuration / version
// returns a DSN suitable for go-sql-driver/mysql.
func startContainerForCase(t *testing.T, ctx context.Context, image string, psEnabled bool) string {
	t.Helper()

	psFlag := "OFF"
	if psEnabled {
		psFlag = "ON"
	}
	cmdArg := fmt.Sprintf("--performance-schema=%s", psFlag)

	switch {
	case strings.HasPrefix(image, "mariadb:"):
		c, err := tcmariadb.Run(ctx, image,
			tcmariadb.WithDatabase("test"),
			tcmariadb.WithUsername("test"),
			tcmariadb.WithPassword("test"),
			testcontainers.WithCmdArgs(cmdArg),
		)
		if err != nil {
			t.Fatalf("starting %s: %v", image, err)
		}
		t.Cleanup(func() {
			_ = c.Terminate(context.Background())
		})
		dsn, err := c.ConnectionString(ctx)
		if err != nil {
			t.Fatalf("MariaDB ConnectionString: %v", err)
		}
		return dsn

	case strings.HasPrefix(image, "mysql:"):
		c, err := tcmysql.Run(ctx, image,
			tcmysql.WithDatabase("test"),
			tcmysql.WithUsername("test"),
			tcmysql.WithPassword("test"),
			testcontainers.WithCmdArgs(cmdArg),
		)
		if err != nil {
			t.Fatalf("starting %s: %v", image, err)
		}
		t.Cleanup(func() {
			_ = c.Terminate(context.Background())
		})
		dsn, err := c.ConnectionString(ctx)
		if err != nil {
			t.Fatalf("MySQL ConnectionString: %v", err)
		}
		return dsn
	default:
		t.Fatalf("Unexpected image / db flavor: %s", image)
		return ""
	}

}
