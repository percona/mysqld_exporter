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

package collector

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"runtime/pprof"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/percona/mysqld_exporter/config"
)

func TestExporterDSN(t *testing.T) {
	const password = "UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+="

	for _, tt := range []struct {
		name string
		dsn  string
		want string
	}{
		{
			name: "special characters in password, no database",
			dsn:  "test:" + password + "@tcp(localhost:3306)/",
			want: "test:" + password + "@tcp(localhost:3306)/?lock_wait_timeout=0",
		},
		{
			name: "special characters in password, with database",
			dsn:  "test:" + password + "@tcp(localhost:3306)/mysql",
			want: "test:" + password + "@tcp(localhost:3306)/mysql?lock_wait_timeout=0",
		},
		{
			name: "special characters in password, with parameter",
			dsn:  "test:" + password + "@tcp(localhost:3306)/?tls=true",
			want: "test:" + password + "@tcp(localhost:3306)/?tls=true&lock_wait_timeout=0",
		},
		{
			name: "special characters in password, with database and parameter",
			dsn:  "test:" + password + "@tcp(localhost:3306)/test?tls=skip-verify",
			want: "test:" + password + "@tcp(localhost:3306)/test?tls=skip-verify&lock_wait_timeout=0",
		},
		{
			name: "unix socket",
			dsn:  "test:" + password + "@unix(/run/mysqld/mysqld.sock)/",
			want: "test:" + password + "@unix(/run/mysqld/mysqld.sock)/?lock_wait_timeout=0",
		},
		{
			name: "unix socket with parameter",
			dsn:  "test:" + password + "@unix(/run/mysqld/mysqld.sock)/?tls=true",
			want: "test:" + password + "@unix(/run/mysqld/mysqld.sock)/?tls=true&lock_wait_timeout=0",
		},
		{
			name: "no network address",
			dsn:  "test:" + password + "@/mysql?tls=true",
			want: "test:" + password + "@/mysql?tls=true&lock_wait_timeout=0",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			exporter := New(t.Context(), tt.dsn, []Scraper{ScrapeGlobalStatus{}}, promslog.NewNopLogger(), EnableLockWaitTimeout(true))
			assert.Equal(t, tt.want, exporter.dsn)
		})
	}
}

func TestGetMySQLVersion(t *testing.T) {
	connDSN := os.Getenv("TEST_MYSQL_DSN")
	if connDSN == "" {
		t.Skip("TEST_MYSQL_DSN is not set")
	}

	instance, err := newInstance(t.Context(), connDSN, 1, 1, 0, nil)
	require.NoError(t, err)
	defer instance.Close()

	assert.GreaterOrEqual(t, instance.versionMajorMinor, 5.7)
	assert.LessOrEqual(t, instance.versionMajorMinor, 11.4)
}

func TestPerconaScrapers(t *testing.T) {
	cfg := config.NewConfigWithDefaults()
	scrapers := make(map[string]Scraper)
	for _, scraper := range AllScrapers(cfg) {
		scrapers[scraper.Name()] = scraper
	}

	// The upstream scrapers replaced by a Percona one stay available under a ".prometheus" suffix.
	for name, want := range map[string]Scraper{
		"global_status":                        PScrapeGlobalStatus{},
		"global_status.prometheus":             ScrapeGlobalStatus{},
		"info_schema.processlist":              PScrapeProcesslist{},
		"info_schema.processlist.prometheus":   ScrapeProcesslist(cfg.InfoSchemaProcesslist),
		"info_schema.innodb_cmp":               PScrapeInnodbCmp{},
		"info_schema.innodb_cmp.prometheus":    ScrapeInnodbCmp{},
		"info_schema.innodb_cmpmem":            PScrapeInnodbCmpMem{},
		"info_schema.innodb_cmpmem.prometheus": ScrapeInnodbCmpMem{},
		"plugins":                              ScrapePlugins{},
		"custom_query.hr":                      ScrapeCustomQuery{Resolution: HR},
		"custom_query.mr":                      ScrapeCustomQuery{Resolution: MR},
		"custom_query.lr":                      ScrapeCustomQuery{Resolution: LR},
	} {
		assert.Equal(t, want, scrapers[name], name)
	}
	assert.IsType(t, standardGo{}, scrapers["standard.go"])
	assert.IsType(t, standardProcess{}, scrapers["standard.process"])

	assert.Empty(t, EnabledScrapers(cfg), "every scraper must be disabled by default")
}

// collectFailingScraper runs a scrape with a scraper that always fails and returns its collector_success value.
func collectFailingScraper(t *testing.T, dsn string, logger *slog.Logger, scrape func() error) float64 {
	t.Helper()

	scraper := &mockScraper{
		name: "failing",
		validate: func(context.Context, *instance) error {
			return scrape()
		},
	}
	exporter := New(t.Context(), dsn, []Scraper{scraper}, logger)

	ch := make(chan prometheus.Metric)
	go func() {
		exporter.Collect(ch)
		close(ch)
	}()

	success := -1.0
	for m := range ch {
		if m.Desc() != mysqlScrapeCollectorSuccess {
			continue
		}
		got := readMetric(m)
		if got.labels["collector"] == "collect.failing" {
			success = got.value
		}
	}
	return success
}

func TestCollectorFailuresLogLevel(t *testing.T) {
	connDSN := os.Getenv("TEST_MYSQL_DSN")
	if connDSN == "" {
		t.Skip("TEST_MYSQL_DSN is not set")
	}

	for _, tt := range []struct {
		name    string
		asError bool
		want    string
	}{
		{name: "debug by default", asError: false, want: `level=DEBUG msg="Error from scraper"`},
		{name: "error when requested", asError: true, want: `level=ERROR msg="Error from scraper"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			previous := *collectorFailuresAsError
			*collectorFailuresAsError = tt.asError
			t.Cleanup(func() {
				*collectorFailuresAsError = previous
			})

			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
			success := collectFailingScraper(t, connDSN, logger, func() error {
				return errors.New("scrape failed")
			})

			assert.Zero(t, success)
			assert.Contains(t, logs.String(), tt.want)
			assert.Contains(t, logs.String(), "scrape failed")
		})
	}
}

func TestScraperGoroutineLabels(t *testing.T) {
	connDSN := os.Getenv("TEST_MYSQL_DSN")
	if connDSN == "" {
		t.Skip("TEST_MYSQL_DSN is not set")
	}

	var profile bytes.Buffer
	success := collectFailingScraper(t, connDSN, promslog.NewNopLogger(), func() error {
		err := pprof.Lookup("goroutine").WriteTo(&profile, 1)
		require.NoError(t, err)
		return errors.New("scrape failed")
	})

	assert.Zero(t, success)
	assert.Contains(t, profile.String(), `"scraper":"failing"`)
}
