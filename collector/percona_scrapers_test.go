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
	"errors"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/blang/semver/v4"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type scrapedMetric struct {
	name   string
	labels labelMap
	value  float64
	vtype  dto.MetricType
}

// scrapeMetrics runs the scraper against the instance and returns every metric it emitted.
func scrapeMetrics(t *testing.T, scraper Scraper, inst *instance) ([]scrapedMetric, error) {
	t.Helper()

	ch := make(chan prometheus.Metric)
	scrapeErr := make(chan error, 1)
	go func() {
		defer close(ch)
		scrapeErr <- scraper.Scrape(t.Context(), inst, ch, promslog.NewNopLogger())
	}()

	var metrics []scrapedMetric
	for metric := range ch {
		match := fqNameRE.FindStringSubmatch(metric.Desc().String())
		require.NotNil(t, match, "cannot parse fqName from %s", metric.Desc())
		got := readMetric(metric)
		metrics = append(metrics, scrapedMetric{name: match[1], labels: got.labels, value: got.value, vtype: got.metricType})
	}
	return metrics, <-scrapeErr
}

func TestPScrapeGlobalStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	const uuid = "6c06e583-686f-11e6-b9e3-8336ad58138c"
	mock.ExpectQuery(sanitizeQuery(pGlobalStatusQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"Variable_name", "Value"}).
			AddRow("Com_alter_db", "1").
			AddRow("Handler_commit", "3").
			AddRow("Connection_errors_internal", "4").
			AddRow("Innodb_buffer_pool_pages_data", "5").
			AddRow("Innodb_buffer_pool_pages_dirty", "7").
			AddRow("Innodb_buffer_pool_pages_flushed", "6").
			AddRow("Innodb_rows_read", "8").
			AddRow("Performance_schema_users_lost", "9").
			AddRow("Slave_running", "OFF").
			AddRow("Ssl_version", "").
			AddRow("Uptime", "10").
			AddRow("wsrep_cluster_status", "Primary").
			AddRow("wsrep_local_state_uuid", uuid).
			AddRow("wsrep_cluster_state_uuid", uuid).
			AddRow("wsrep_provider_version", "3.16(r5c765eb)").
			AddRow("wsrep_evs_repl_latency", "0.000227664/0.00034135/0.000544298/6.03708e-05/212"))

	metrics, err := scrapeMetrics(t, PScrapeGlobalStatus{}, &instance{db: db})
	require.NoError(t, err)

	assert.Equal(t, []scrapedMetric{
		{name: "mysql_global_status_commands_total", labels: labelMap{"command": "alter_db"}, value: 1, vtype: dto.MetricType_COUNTER},
		{name: "mysql_global_status_handlers_total", labels: labelMap{"handler": "commit"}, value: 3, vtype: dto.MetricType_COUNTER},
		{name: "mysql_global_status_connection_errors_total", labels: labelMap{"error": "internal"}, value: 4, vtype: dto.MetricType_COUNTER},
		{name: "mysql_global_status_buffer_pool_pages", labels: labelMap{"state": "data"}, value: 5, vtype: dto.MetricType_GAUGE},
		{name: "mysql_global_status_buffer_pool_dirty_pages", labels: labelMap{"dirty": "dirty"}, value: 7, vtype: dto.MetricType_GAUGE},
		{name: "mysql_global_status_buffer_pool_page_changes_total", labels: labelMap{"operation": "flushed"}, value: 6, vtype: dto.MetricType_COUNTER},
		{name: "mysql_global_status_innodb_row_ops_total", labels: labelMap{"operation": "read"}, value: 8, vtype: dto.MetricType_COUNTER},
		{name: "mysql_global_status_performance_schema_lost_total", labels: labelMap{"instrumentation": "users_lost"}, value: 9, vtype: dto.MetricType_COUNTER},
		{name: "mysql_global_status_slave_running", labels: labelMap{}, value: 0, vtype: dto.MetricType_UNTYPED},
		{name: "mysql_global_status_uptime", labels: labelMap{}, value: 10, vtype: dto.MetricType_UNTYPED},
		{name: "mysql_global_status_wsrep_cluster_status", labels: labelMap{}, value: 1, vtype: dto.MetricType_UNTYPED},
		{
			name:   "mysql_galera_status_info",
			labels: labelMap{"wsrep_local_state_uuid": uuid, "wsrep_cluster_state_uuid": uuid, "wsrep_provider_version": "3.16(r5c765eb)"},
			value:  1,
			vtype:  dto.MetricType_GAUGE,
		},
		{name: "mysql_galera_evs_repl_latency_min_seconds", labels: labelMap{}, value: 0.000227664, vtype: dto.MetricType_GAUGE},
		{name: "mysql_galera_evs_repl_latency_avg_seconds", labels: labelMap{}, value: 0.00034135, vtype: dto.MetricType_GAUGE},
		{name: "mysql_galera_evs_repl_latency_max_seconds", labels: labelMap{}, value: 0.000544298, vtype: dto.MetricType_GAUGE},
		{name: "mysql_galera_evs_repl_latency_stdev", labels: labelMap{}, value: 6.03708e-05, vtype: dto.MetricType_GAUGE},
		{name: "mysql_galera_evs_repl_latency_sample_size", labels: labelMap{}, value: 212, vtype: dto.MetricType_GAUGE},
	}, metrics)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPScrapeInnodbCmp(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	columns := []string{"page_size", "compress_ops", "compress_ops_ok", "compress_time", "uncompress_ops", "uncompress_time", "extra"}
	mock.ExpectQuery(sanitizeQuery(pInnodbCmpQuery)).
		WillReturnRows(sqlmock.NewRows(columns).AddRow("1024", 10, 20, 30, 40, 50, 60))

	metrics, err := scrapeMetrics(t, PScrapeInnodbCmp{}, &instance{db: db})
	require.NoError(t, err)

	labels := labelMap{"page_size": "1024"}
	assert.Equal(t, []scrapedMetric{
		{name: "mysql_info_schema_innodb_cmp_compress_ops_total", labels: labels, value: 10, vtype: dto.MetricType_COUNTER},
		{name: "mysql_info_schema_innodb_cmp_compress_ops_ok_total", labels: labels, value: 20, vtype: dto.MetricType_COUNTER},
		{name: "mysql_info_schema_innodb_cmp_compress_time_seconds_total", labels: labels, value: 30, vtype: dto.MetricType_COUNTER},
		{name: "mysql_info_schema_innodb_cmp_uncompress_ops_total", labels: labels, value: 40, vtype: dto.MetricType_COUNTER},
		{name: "mysql_info_schema_innodb_cmp_uncompress_time_seconds_total", labels: labels, value: 50, vtype: dto.MetricType_COUNTER},
		{name: "mysql_info_schema_innodb_cmp_extra", labels: labels, value: 60, vtype: dto.MetricType_UNTYPED},
	}, metrics)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPScrapeInnodbCmpQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(sanitizeQuery(pInnodbCmpQuery)).WillReturnError(errors.New("no such table"))

	metrics, err := scrapeMetrics(t, PScrapeInnodbCmp{}, &instance{db: db})
	require.Error(t, err)
	assert.Empty(t, metrics)
}

func TestPScrapeInnodbCmpMem(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	columns := []string{"page_size", "buffer_pool_instance", "pages_used", "pages_free", "relocation_ops", "relocation_time"}
	mock.ExpectQuery(sanitizeQuery(pInnodbCmpMemQuery)).
		WillReturnRows(sqlmock.NewRows(columns).AddRow("1024", "0", 30, 40, 50, 6000))

	metrics, err := scrapeMetrics(t, PScrapeInnodbCmpMem{}, &instance{db: db})
	require.NoError(t, err)

	labels := labelMap{"page_size": "1024", "buffer": "0"}
	assert.Equal(t, []scrapedMetric{
		{name: "mysql_info_schema_innodb_cmpmem_pages_used_total", labels: labels, value: 30, vtype: dto.MetricType_COUNTER},
		{name: "mysql_info_schema_innodb_cmpmem_pages_free_total", labels: labels, value: 40, vtype: dto.MetricType_COUNTER},
		{name: "mysql_info_schema_innodb_cmpmem_relocation_ops_total", labels: labels, value: 50, vtype: dto.MetricType_COUNTER},
		{name: "mysql_info_schema_innodb_cmpmem_relocation_time_seconds_total", labels: labels, value: 6, vtype: dto.MetricType_COUNTER},
	}, metrics)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStandardScrapers(t *testing.T) {
	for _, tt := range []struct {
		scraper Scraper
		name    string
		metric  string
	}{
		{scraper: NewStandardGo(), name: "standard.go", metric: "go_goroutines"},
		{scraper: NewStandardProcess(), name: "standard.process", metric: "process_cpu_seconds_total"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.name, tt.scraper.Name())
			assert.Zero(t, tt.scraper.Version(), "must not depend on the MySQL version")

			metrics, err := scrapeMetrics(t, tt.scraper, &instance{})
			require.NoError(t, err)

			var names []string
			for _, metric := range metrics {
				names = append(names, metric.name)
			}
			assert.Contains(t, names, tt.metric)
		})
	}
}

func TestDeriveThreadState(t *testing.T) {
	for _, tt := range []struct {
		command string
		state   string
		want    string
	}{
		{command: "Query", state: "Sending data", want: "sending data"},
		{command: "Query", state: "Sending_data", want: "sending data"},
		{command: "Query", state: "User sleep", want: "idle"},
		{command: "Query", state: "copy to tmp table", want: "copying to tmp table"},
		{command: "Query", state: "Waiting for table metadata lock", want: "waiting for lock"},
		{command: "Connect", state: "Waiting for an event from Coordinator", want: "waiting for an event from coordinator"},
		{command: "Sleep", state: "", want: "idle"},
		{command: "Query", state: "something new", want: "executing"},
		{command: "Binlog Dump", state: "Master has sent all binlog to slave", want: "replication master"},
		{command: "Daemon", state: "something new", want: "other"},
	} {
		t.Run(fmt.Sprintf("%s/%s", tt.command, tt.state), func(t *testing.T) {
			assert.Equal(t, tt.want, deriveThreadState(tt.command, tt.state))
		})
	}
}

func TestPScrapeProcesslistMetrics(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	query := fmt.Sprintf(pInfoSchemaProcesslistQuery, processlistInfoSchema, *pProcesslistMinTime)
	mock.ExpectQuery(sanitizeQuery(query)).
		WillReturnRows(sqlmock.NewRows([]string{"command", "state", "count", "time"}).
			AddRow("Query", "Sending data", 2, 10).
			AddRow("Query", "sending data", 1, 5).
			AddRow("Sleep", "", 4, 100).
			AddRow("Daemon", "something new", 1, 7))

	inst := &instance{db: db, flavor: FlavorMariaDB, version: semver.MustParse("10.11.0")}
	metrics, err := scrapeMetrics(t, PScrapeProcesslist{}, inst)
	require.NoError(t, err)

	counts := make(map[string]float64)
	seconds := make(map[string]float64)
	for _, metric := range metrics {
		switch metric.name {
		case "mysql_info_schema_threads":
			counts[metric.labels["state"]] = metric.value
		case "mysql_info_schema_threads_seconds":
			seconds[metric.labels["state"]] = metric.value
		default:
			t.Errorf("unexpected metric %s", metric.name)
		}
	}

	// Every known state is reported, the ones without threads as zero.
	assert.Len(t, counts, len(threadStateCounterMap))
	assert.Len(t, seconds, len(threadStateCounterMap))
	assert.InDelta(t, 3, counts["sending data"], 0)
	assert.InDelta(t, 15, seconds["sending data"], 0)
	assert.InDelta(t, 4, counts["idle"], 0)
	assert.InDelta(t, 100, seconds["idle"], 0)
	assert.InDelta(t, 1, counts["other"], 0)
	assert.InDelta(t, 7, seconds["other"], 0)
	assert.Zero(t, counts["executing"])
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestNewInstanceFromDB(t *testing.T) {
	for _, tt := range []struct {
		name            string
		version         string
		perfSchema      int
		wantFlavor      string
		wantVersion     string
		wantMajorMinor  float64
		wantPerfSchema  bool
		perfSchemaError error
	}{
		{name: "MySQL with performance_schema", version: "8.0.36-28.1", perfSchema: 1, wantFlavor: FlavorMySQL, wantVersion: "8.0.36", wantMajorMinor: 8.0, wantPerfSchema: true},
		{name: "MySQL without performance_schema", version: "5.7.44-log", perfSchema: 0, wantFlavor: FlavorMySQL, wantVersion: "5.7.44", wantMajorMinor: 5.7},
		{name: "MariaDB", version: "10.5.17-MariaDB-1:10.5.17+maria~ubu2004-log", perfSchema: 1, wantFlavor: FlavorMariaDB, wantVersion: "10.5.17", wantMajorMinor: 10.5, wantPerfSchema: true},
		{name: "performance_schema query fails", version: "8.0.36", perfSchemaError: errors.New("access denied")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			require.NoError(t, err)
			defer db.Close()

			mock.ExpectQuery(versionQuery).WillReturnRows(sqlmock.NewRows([]string{"@@version"}).AddRow(tt.version))
			perfSchemaQuery := mock.ExpectQuery(performanceSchemaQuery)
			if tt.perfSchemaError != nil {
				perfSchemaQuery.WillReturnError(tt.perfSchemaError)
				mock.ExpectClose()
			} else {
				perfSchemaQuery.WillReturnRows(sqlmock.NewRows([]string{"@@performance_schema"}).AddRow(tt.perfSchema))
			}

			inst, err := newInstanceFromDB(t.Context(), db)
			if tt.perfSchemaError != nil {
				require.ErrorIs(t, err, tt.perfSchemaError)
				assert.Nil(t, inst)
				require.NoError(t, mock.ExpectationsWereMet(), "the connection must be closed on failure")
				return
			}
			require.NoError(t, err)

			assert.Same(t, db, inst.getDB())
			assert.Equal(t, tt.wantFlavor, inst.flavor)
			assert.Equal(t, tt.wantVersion, inst.version.String())
			assert.InDelta(t, tt.wantMajorMinor, inst.versionMajorMinor, 0)
			assert.Equal(t, tt.wantPerfSchema, inst.isPerformanceSchemaEnabled)
			require.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestNewInstanceFromDBVersionError(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	require.NoError(t, err)
	defer db.Close()

	mock.ExpectQuery(versionQuery).WillReturnRows(sqlmock.NewRows([]string{"@@version"}).AddRow("unknown"))
	mock.ExpectClose()

	inst, err := newInstanceFromDB(t.Context(), db)
	require.Error(t, err)
	assert.Nil(t, inst)
	require.NoError(t, mock.ExpectationsWereMet(), "the connection must be closed on failure")
}

func TestScrapeTableSchemaDisablesStatsExpiry(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// sqlmock enforces the order: the session variable has to be set before the tables are read.
	mock.ExpectExec(sanitizeQuery("/*!80000 set session information_schema_stats_expiry=0 */")).
		WillReturnResult(sqlmock.NewResult(0, 0))
	columns := []string{"TABLE_SCHEMA", "TABLE_NAME", "TABLE_TYPE", "ENGINE", "VERSION", "ROW_FORMAT", "TABLE_ROWS", "DATA_LENGTH", "INDEX_LENGTH", "DATA_FREE", "CREATE_OPTIONS"}
	mock.ExpectQuery(sanitizeQuery(tableSchemaQuery)).
		WithArgs("db1").
		WillReturnRows(sqlmock.NewRows(columns).AddRow("db1", "t1", "BASE TABLE", "InnoDB", 10, "Dynamic", 42, 16384, 0, 0, ""))

	metrics, err := scrapeMetrics(t, ScrapeTableSchema{Databases: "db1"}, &instance{db: db})
	require.NoError(t, err)

	rows := -1.0
	for _, metric := range metrics {
		if metric.name == "mysql_info_schema_table_rows" {
			assert.Equal(t, labelMap{"schema": "db1", "table": "t1"}, metric.labels)
			rows = metric.value
		}
	}
	assert.InDelta(t, 42, rows, 0)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestScrapeTableSchemaStatsExpiryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	failure := errors.New("connection lost")
	mock.ExpectExec(sanitizeQuery("/*!80000 set session information_schema_stats_expiry=0 */")).WillReturnError(failure)

	metrics, err := scrapeMetrics(t, ScrapeTableSchema{Databases: "db1"}, &instance{db: db})
	require.ErrorIs(t, err, failure)
	assert.Empty(t, metrics)
}
