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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/percona/mysqld_exporter/collector"
	"github.com/percona/mysqld_exporter/config"
)

// parseFlags parses args the way main does and restores every flag default afterwards.
func parseFlags(t *testing.T, args ...string) {
	t.Helper()

	reset := func() {
		perconaMaxOpenConnsSet = false
		perconaMaxIdleConnsSet = false
		perconaConnMaxLifetimeSet = false
		_, err := kingpin.CommandLine.Parse(nil)
		require.NoError(t, err)
	}
	reset()
	t.Cleanup(reset)

	_, err := kingpin.CommandLine.Parse(args)
	require.NoError(t, err)
	applyPerconaFlagAliases()
}

func TestPerconaConnectionPoolFlags(t *testing.T) {
	for _, tt := range []struct {
		name        string
		args        []string
		wantMaxOpen int
		wantMaxIdle int
		wantLife    time.Duration
	}{
		{
			name:        "defaults",
			wantMaxOpen: 3,
			wantMaxIdle: 3,
			wantLife:    time.Minute,
		},
		{
			name:        "aliases as passed by pmm-managed",
			args:        []string{"--exporter.max-idle-conns=3", "--exporter.max-open-conns=3", "--exporter.conn-max-lifetime=55s"},
			wantMaxOpen: 3,
			wantMaxIdle: 3,
			wantLife:    55 * time.Second,
		},
		{
			name:        "aliases",
			args:        []string{"--exporter.max-open-conns=7", "--exporter.max-idle-conns=5", "--exporter.conn-max-lifetime=2m"},
			wantMaxOpen: 7,
			wantMaxIdle: 5,
			wantLife:    2 * time.Minute,
		},
		{
			name:        "single alias keeps the other defaults",
			args:        []string{"--exporter.max-open-conns=9"},
			wantMaxOpen: 9,
			wantMaxIdle: 3,
			wantLife:    time.Minute,
		},
		{
			name:        "alias set to zero",
			args:        []string{"--exporter.max-idle-conns=0", "--exporter.conn-max-lifetime=0s"},
			wantMaxOpen: 3,
			wantMaxIdle: 0,
			wantLife:    0,
		},
		{
			name:        "alias takes precedence over the upstream flag",
			args:        []string{"--exporter.max_open_connections=4", "--exporter.max-open-conns=6"},
			wantMaxOpen: 6,
			wantMaxIdle: 3,
			wantLife:    time.Minute,
		},
		{
			name:        "upstream flags",
			args:        []string{"--exporter.max_open_connections=4", "--exporter.max_idle_connections=2", "--exporter.conn_max_lifetime=30s"},
			wantMaxOpen: 4,
			wantMaxIdle: 2,
			wantLife:    30 * time.Second,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parseFlags(t, tt.args...)

			cfg := configFromFlags(nil)
			assert.Equal(t, tt.wantMaxOpen, cfg.ExporterMaxOpenConns)
			assert.Equal(t, tt.wantMaxIdle, cfg.ExporterMaxIdleConns)
			assert.Equal(t, tt.wantLife, cfg.ExporterConnMaxLifetime)
		})
	}
}

func TestPerconaFlagValidation(t *testing.T) {
	// The pool flags and --timeout-offset accept any value; zero or less means "no limit" for the pool.
	parseFlags(t, "--exporter.max-open-conns=0", "--exporter.max-idle-conns=-1", "--exporter.conn-max-lifetime=-1s", "--timeout-offset=-1")
	require.NoError(t, validatePerconaFlags())

	cfg := configFromFlags(nil)
	cfg.DataSourceName = "root@tcp(localhost:3306)/"
	assert.Equal(t, 0, cfg.ExporterMaxOpenConns)
	assert.Equal(t, -1, cfg.ExporterMaxIdleConns)
	assert.Equal(t, -time.Second, cfg.ExporterConnMaxLifetime)
	_, err := collector.NewRuntimeWithContext(t.Context(), cfg, promslog.NewNopLogger())
	require.NoError(t, err)

	parseFlags(t, "--exporter.query_timeout=-1")
	require.Error(t, validatePerconaFlags())
}

func TestPerconaFlagDefaults(t *testing.T) {
	parseFlags(t)

	// The fork's defaults, which a sync with upstream keeps.
	cfg := configFromFlags(nil)
	for name, enabled := range cfg.Collectors {
		assert.False(t, enabled, name)
	}
	cfg.Collectors = nil
	assert.Equal(t, config.Config{
		EnableExporterLockWaitTimeout:  true,
		ExporterLockWaitTimeoutSeconds: 2,
		ExporterMaxOpenConns:           3,
		ExporterMaxIdleConns:           3,
		ExporterConnMaxLifetime:        time.Minute,
		Heartbeat:                      config.HeartbeatConfig{Database: "heartbeat", Table: "heartbeat"},
		InfoSchemaProcesslist:          config.InfoSchemaProcesslistConfig{ProcessesByUser: true, ProcessesByHost: true},
		InfoSchemaTables:               config.InfoSchemaTablesConfig{Databases: "*"},
		PerfSchemaEventsStatements:     config.PerfSchemaEventsStatementsConfig{Limit: 250, TimeLimit: 86400, DigestTextLimit: 120},
		PerfSchemaFileInstances:        config.PerfSchemaFileInstancesConfig{Filter: ".*", RemovePrefix: "/var/lib/mysql/"},
		PerfSchemaMemoryEvents:         config.PerfSchemaMemoryEventsConfig{RemovePrefix: "memory/"},
	}, cfg)

	assert.Equal(t, path.Join(os.Getenv("HOME"), ".my.cnf"), *configMycnf)
	assert.Equal(t, "localhost:3306", *mysqldAddress)
	assert.Equal(t, "/metrics", *metricsPath)
	assert.InDelta(t, 0.25, *timeoutOffset, 1e-9)
	assert.False(t, *tlsInsecureSkipVerify)
	assert.False(t, *collectAll)

	// The aliases carry the defaults themselves, so --help shows them next to the flag names PMM uses.
	for name, want := range map[string]string{
		"exporter.max-open-conns":                  "3",
		"exporter.max-idle-conns":                  "3",
		"exporter.conn-max-lifetime":               "1m0s",
		"collect.info_schema.processlist.min_time": "0",
		"web.listen-address":                       ":9104",
	} {
		assert.Equal(t, []string{want}, kingpin.CommandLine.GetFlag(name).Model().Default, name)
	}
}

func TestPerconaProcesslistMinTimeFlags(t *testing.T) {
	// Percona's processlist scraper owns the upstream flag name, the upstream scraper reads the suffixed one.
	parseFlags(t, "--collect.info_schema.processlist.min_time=5", "--collect.info_schema.processlist.min_time.prometheus=7")

	assert.Equal(t, 7, configFromFlags(nil).InfoSchemaProcesslist.MinTime)
}

func TestCollectAllFlag(t *testing.T) {
	scraperFlags := make(map[string]*bool)
	for _, scraper := range collector.AllScrapers(config.NewConfigWithDefaults()) {
		scraperFlags[scraper.Name()] = new(bool)
	}

	parseFlags(t)
	assert.Empty(t, collector.EnabledScrapers(configFromFlags(scraperFlags)))

	parseFlags(t, "--collect.all")
	assert.Len(t, collector.EnabledScrapers(configFromFlags(scraperFlags)), len(scraperFlags))
}

// setAuthConfig points the exporter to a MySQL server at address for the duration of the test.
func setAuthConfig(t *testing.T, address string) {
	t.Helper()

	handler, err := config.NewAuthConfigHandler(prometheus.NewRegistry())
	require.NoError(t, err)
	err = handler.ReloadConfig("", address, "root", false, promslog.NewNopLogger())
	require.NoError(t, err)

	previous := c
	c = handler
	t.Cleanup(func() {
		c = previous
	})
}

// closedAddress returns a local address that refuses connections.
func closedAddress(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	return address
}

func scrape(handler http.HandlerFunc, ctx context.Context, collect string) *httptest.ResponseRecorder {
	target := "/metrics"
	if collect != "" {
		target += "?collect[]=" + collect
	}
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodGet, target, nil).WithContext(ctx))
	return recorder
}

func TestHandlerReportsUnusableCertificateAsDown(t *testing.T) {
	dir := t.TempDir()
	caFile := path.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, []byte("not a certificate\n"), 0o600))
	cnf := path.Join(dir, "my.cnf")
	require.NoError(t, os.WriteFile(cnf, []byte("[client]\nuser=root\nhost=127.0.0.1\nssl-ca="+caFile+"\n"), 0o600))

	handler, err := config.NewAuthConfigHandler(prometheus.NewRegistry())
	require.NoError(t, err)
	require.NoError(t, handler.ReloadConfig(cnf, "localhost:3306", "", false, promslog.NewNopLogger()))
	previous := c
	c = handler
	t.Cleanup(func() {
		c = previous
	})

	recorder := scrape(newHandler(config.NewConfigWithDefaults(), 0, promslog.NewNopLogger()), t.Context(), "")
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "\nmysql_up 0\n")
}

func TestHandlerDefaultGatherer(t *testing.T) {
	setAuthConfig(t, closedAddress(t))

	cfg := config.NewConfigWithDefaults()
	cfg.Collectors["global_status"] = true
	cfg.Collectors["standard.go"] = true
	handler := newHandler(cfg, 0, promslog.NewNopLogger())

	// go_goroutines comes from the default gatherer here, the scrapers do not run without a database.
	for _, tt := range []struct {
		name        string
		collect     string
		wantDefault bool
	}{
		{name: "without standard collectors", collect: "global_status", wantDefault: true},
		{name: "standard collector requested", collect: "standard.go", wantDefault: false},
		{name: "all enabled collectors", collect: "", wantDefault: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			recorder := scrape(handler, t.Context(), tt.collect)

			require.Equal(t, http.StatusOK, recorder.Code)
			body := recorder.Body.String()
			assert.Contains(t, body, "mysql_up 0")
			if tt.wantDefault {
				assert.Contains(t, body, "go_goroutines")
			} else {
				assert.NotContains(t, body, "go_goroutines")
			}
		})
	}
}

type failingCollector struct {
	desc *prometheus.Desc
}

func (c failingCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c failingCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.NewInvalidMetric(c.desc, errors.New("collection failed"))
}

func TestHandlerContinuesOnCollectorError(t *testing.T) {
	failing := failingCollector{desc: prometheus.NewDesc("mysqld_exporter_test_failing", "Always fails.", nil, nil)}
	require.NoError(t, prometheus.Register(failing))
	t.Cleanup(func() {
		prometheus.Unregister(failing)
	})

	setAuthConfig(t, closedAddress(t))

	cfg := config.NewConfigWithDefaults()
	cfg.Collectors["global_status"] = true
	var logs bytes.Buffer
	handler := newHandler(cfg, 0, slog.New(slog.NewTextHandler(&logs, nil)))

	recorder := scrape(handler, t.Context(), "global_status")

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "mysql_up 0")
	assert.Contains(t, logs.String(), "collection failed")
}

func TestHandlerRejectsConcurrentCustomQueryScrapes(t *testing.T) {
	// A server that accepts connections and never answers keeps a scrape in flight.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	accepted := make(chan net.Conn, 16)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- conn
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		for conn := range accepted {
			_ = conn.Close()
		}
	})

	setAuthConfig(t, listener.Addr().String())

	cfg := config.NewConfigWithDefaults()
	for _, name := range []string{"custom_query.hr", "custom_query.mr", "custom_query.lr", "global_status"} {
		cfg.Collectors[name] = true
	}
	handler := newHandler(cfg, 0, promslog.NewNopLogger())

	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	for _, resolution := range []string{"hr", "mr", "lr"} {
		t.Run(resolution, func(t *testing.T) {
			collect := "custom_query." + resolution

			inFlight, finish := context.WithCancel(t.Context())
			defer finish()
			first := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				first <- scrape(handler, inFlight, collect)
			}()

			select {
			case conn := <-accepted:
				defer conn.Close()
			case <-time.After(10 * time.Second):
				t.Fatal("the first scrape did not reach the database")
			}

			assert.Equal(t, http.StatusTooManyRequests, scrape(handler, canceled, collect).Code)
			assert.Equal(t, http.StatusOK, scrape(handler, canceled, "global_status").Code, "other scrapes are not limited")

			finish()
			select {
			case recorder := <-first:
				assert.Equal(t, http.StatusOK, recorder.Code)
			case <-time.After(10 * time.Second):
				t.Fatal("the first scrape did not finish")
			}

			assert.Equal(t, http.StatusOK, scrape(handler, canceled, collect).Code, "the slot is free again")
		})
	}
}

// testPprof checks that the binary serves the Go profiling endpoints.
func testPprof(t *testing.T, data bin) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(
		ctx,
		data.path,
		"--web.listen-address", fmt.Sprintf(":%d", data.port),
		"--config.my-cnf=test_exporter.cnf",
	)
	require.NoError(t, cmd.Start())
	defer cmd.Wait()
	defer cmd.Process.Kill()

	body, err := waitForBody(fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/cmdline", data.port))
	require.NoError(t, err)
	assert.Contains(t, string(body), data.path)
}
