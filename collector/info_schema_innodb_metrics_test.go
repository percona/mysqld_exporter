// Copyright 2018 The Prometheus Authors
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
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/smartystreets/goconvey/convey"
)

func TestScrapeInnodbMetrics(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()
	inst := &instance{db: db}

	enabledColumnName := []string{"COLUMN_NAME"}
	rows := sqlmock.NewRows(enabledColumnName).
		AddRow("STATUS")
	mock.ExpectQuery(sanitizeQuery(infoSchemaInnodbMetricsEnabledColumnQuery)).WillReturnRows(rows)

	columns := []string{"name", "subsystem", "type", "comment", "count"}
	rows = sqlmock.NewRows(columns).
		AddRow("lock_timeouts", "lock", "counter", "Number of lock timeouts", 0).
		AddRow("buffer_pool_reads", "buffer", "status_counter", "Number of reads directly from disk (innodb_buffer_pool_reads)", 1).
		AddRow("buffer_pool_size", "server", "value", "Server buffer pool size (all buffer pools) in bytes", 2).
		AddRow("buffer_page_read_system_page", "buffer_page_io", "counter", "Number of System Pages read", 3).
		AddRow("buffer_page_written_undo_log", "buffer_page_io", "counter", "Number of Undo Log Pages written", 4).
		AddRow("buffer_pool_pages_dirty", "buffer", "gauge", "Number of dirt buffer pool pages", 5).
		AddRow("buffer_pool_pages_data", "buffer", "gauge", "Number of data buffer pool pages", 6).
		AddRow("buffer_pool_pages_total", "buffer", "gauge", "Number of total buffer pool pages", 7).
		AddRow("NOPE", "buffer_page_io", "counter", "An invalid buffer_page_io metric", 999)
	query := fmt.Sprintf(infoSchemaInnodbMetricsQuery, "status", "enabled")
	mock.ExpectQuery(sanitizeQuery(query)).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		if err = (ScrapeInnodbMetrics{}).Scrape(context.Background(), inst, ch, promslog.NewNopLogger()); err != nil {
			t.Errorf("error calling function on test: %s", err)
		}
		close(ch)
	}()

	metricExpected := []MetricResult{
		{labels: labelMap{}, value: 0, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{}, value: 1, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{}, value: 2, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"type": "system_page"}, value: 3, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"type": "undo_log"}, value: 4, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{}, value: 5, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"state": "data"}, value: 6, metricType: dto.MetricType_GAUGE},
	}
	convey.Convey("Metrics comparison", t, func() {
		for _, expect := range metricExpected {
			got := readMetric(<-ch)
			convey.So(got, convey.ShouldResemble, expect)
		}
	})

	// Ensure all SQL queries were executed
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled exceptions: %s", err)
	}
}

func TestScrapeInnodbMetricsStableAliases(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()
	inst := &instance{db: db}

	mock.ExpectQuery(sanitizeQuery(infoSchemaInnodbMetricsEnabledColumnQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"COLUMN_NAME"}).AddRow("STATUS"))

	rows := sqlmock.NewRows([]string{"name", "subsystem", "type", "comment", "count"}).
		AddRow("buffer_flush_neighbor", "buffer", "set_member", "Neighbor flush batches", 2).
		AddRow("buffer_flush_neighbor_total_pages", "buffer", "set_owner", "Neighbor flush pages", 8).
		AddRow("buffer_flush_batch_scanned_per_call", "buffer", "set_member", "Pages scanned per flush batch", 4).
		AddRow("buffer_flush_batch_total_pages", "buffer", "set_owner", "Pages flushed by batches", 6).
		AddRow("trx_rw_commits", "transaction", "status_counter", "Read-write commits", 3).
		AddRow("log_lsn_checkpoint_age", "log", "counter", "Checkpoint age", 12).
		AddRow("log_lsn_checkpoint_age", "recovery", "counter", "Checkpoint age", 14)
	query := fmt.Sprintf(infoSchemaInnodbMetricsQuery, "status", "enabled")
	mock.ExpectQuery(sanitizeQuery(query)).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		defer close(ch)
		if scrapeErr := (ScrapeInnodbMetrics{}).Scrape(t.Context(), inst, ch, promslog.NewNopLogger()); scrapeErr != nil {
			t.Errorf("error calling function on test: %s", scrapeErr)
		}
	}()

	type expectedMetric struct {
		value      float64
		metricType dto.MetricType
	}
	expected := map[string]expectedMetric{
		"mysql_innodb_metrics_buffer_flush_neighbor_batches_total": {
			value: 2, metricType: dto.MetricType_COUNTER,
		},
		"mysql_innodb_metrics_buffer_flush_neighbor_pages_total": {
			value: 8, metricType: dto.MetricType_COUNTER,
		},
		"mysql_innodb_metrics_transactions_read_write_committed_total": {
			value: 3, metricType: dto.MetricType_COUNTER,
		},
		// A counter row in stableInnodbMetrics must leave the generic series
		// exactly as it was before the alias existed: one "_total" counter.
		"mysql_info_schema_innodb_metrics_transaction_trx_rw_commits_total": {
			value: 3, metricType: dto.MetricType_COUNTER,
		},
		"mysql_info_schema_innodb_metrics_buffer_buffer_flush_neighbor_total": {
			value: 2, metricType: dto.MetricType_COUNTER,
		},
		"mysql_info_schema_innodb_metrics_buffer_buffer_flush_neighbor_total_pages": {
			value: 8, metricType: dto.MetricType_GAUGE,
		},
		"mysql_info_schema_innodb_metrics_buffer_buffer_flush_neighbor_total_pages_total": {
			value: 8, metricType: dto.MetricType_COUNTER,
		},
		"mysql_info_schema_innodb_metrics_buffer_buffer_flush_batch_scanned_per_call": {
			value: 4, metricType: dto.MetricType_GAUGE,
		},
		"mysql_info_schema_innodb_metrics_buffer_buffer_flush_batch_total_pages": {
			value: 6, metricType: dto.MetricType_GAUGE,
		},
		"mysql_info_schema_innodb_metrics_log_log_lsn_checkpoint_age": {
			value: 12, metricType: dto.MetricType_GAUGE,
		},
		"mysql_info_schema_innodb_metrics_log_log_lsn_checkpoint_age_total": {
			value: 12, metricType: dto.MetricType_COUNTER,
		},
		"mysql_info_schema_innodb_metrics_recovery_log_lsn_checkpoint_age": {
			value: 14, metricType: dto.MetricType_GAUGE,
		},
		"mysql_info_schema_innodb_metrics_recovery_log_lsn_checkpoint_age_total": {
			value: 14, metricType: dto.MetricType_COUNTER,
		},
	}
	unexpected := []string{
		// Derived set members must not be exported as counters.
		"mysql_info_schema_innodb_metrics_buffer_buffer_flush_batch_scanned_per_call_total",
		// Set owners outside stableInnodbMetrics must keep their historical
		// gauge type instead of silently turning into counters.
		"mysql_info_schema_innodb_metrics_buffer_buffer_flush_batch_total_pages_total",
		// Membership in stableInnodbMetrics must not add an unsuffixed gauge to
		// a counter row. Only the set_member/set_owner rows gain a second
		// series, so ten of the twelve entries are a pure rename and this is
		// what pins that.
		"mysql_info_schema_innodb_metrics_transaction_trx_rw_commits",
	}
	found := make(map[string]bool, len(expected))
	for metric := range ch {
		desc := metric.Desc().String()
		for _, name := range unexpected {
			if strings.Contains(desc, `fqName: "`+name+`"`) {
				t.Errorf("metric %s must not be exported", name)
			}
		}
		for name, want := range expected {
			if !strings.Contains(desc, `fqName: "`+name+`"`) {
				continue
			}
			got := readMetric(metric)
			if got.value != want.value {
				t.Errorf("metric %s value = %v, want %v", name, got.value, want.value)
			}
			if got.metricType != want.metricType {
				t.Errorf("metric %s type = %v, want %v", name, got.metricType, want.metricType)
			}
			found[name] = true
		}
	}
	for name := range expected {
		if !found[name] {
			t.Errorf("stable metric %s was not collected", name)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestScrapeInnodbMetricsGaugeOverrideSkipsNegative(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()
	inst := &instance{db: db}

	mock.ExpectQuery(sanitizeQuery(infoSchemaInnodbMetricsEnabledColumnQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"COLUMN_NAME"}).AddRow("STATUS"))

	// The -1 sentinel is reported by some MySQL versions due to an upstream
	// INNODB_METRICS bug and must not be exported for gauge-override metrics.
	rows := sqlmock.NewRows([]string{"name", "subsystem", "type", "comment", "count"}).
		AddRow("log_lsn_checkpoint_age", "log", "counter", "Checkpoint age", -1)
	query := fmt.Sprintf(infoSchemaInnodbMetricsQuery, "status", "enabled")
	mock.ExpectQuery(sanitizeQuery(query)).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		defer close(ch)
		if scrapeErr := (ScrapeInnodbMetrics{}).Scrape(t.Context(), inst, ch, promslog.NewNopLogger()); scrapeErr != nil {
			t.Errorf("error calling function on test: %s", scrapeErr)
		}
	}()

	for metric := range ch {
		if strings.Contains(metric.Desc().String(), "log_lsn_checkpoint_age") {
			t.Errorf("negative override metric should be skipped, got: %s", metric.Desc())
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

// scraperCollector adapts a Scraper to prometheus.Collector so that a test can
// gather through a registry. Two metrics sharing an fqName, or one fqName
// exported as both a gauge and a counter, are only detected by Gather(), and a
// single occurrence costs the whole metric family on the endpoint.
type scraperCollector struct {
	t       *testing.T
	ctx     context.Context
	scraper Scraper
	inst    *instance
}

func (c scraperCollector) Describe(chan<- *prometheus.Desc) {}

func (c scraperCollector) Collect(ch chan<- prometheus.Metric) {
	if err := c.scraper.Scrape(c.ctx, c.inst, ch, promslog.NewNopLogger()); err != nil {
		c.t.Errorf("error calling function on test: %s", err)
	}
}

func TestScrapeInnodbMetricsGathersThroughRegistry(t *testing.T) {
	columns := []string{"name", "subsystem", "type", "comment", "count"}
	cases := []struct {
		name     string
		rows     func() *sqlmock.Rows
		expected []string
	}{
		{
			// Subsystems and types as reported by MySQL 8.0, 8.4, 9.7 and
			// Percona Server 8.0.
			name: "MySQL 8.0 and newer",
			rows: func() *sqlmock.Rows {
				return sqlmock.NewRows(columns).
					AddRow("buffer_flush_neighbor", "buffer", "set_member", "Neighbor flush batches", 2).
					AddRow("buffer_flush_neighbor_total_pages", "buffer", "set_owner", "Neighbor flush pages", 8).
					AddRow("purge_invoked", "purge", "counter", "Purge invocations", 5).
					AddRow("trx_rw_commits", "transaction", "counter", "Read-write commits", 3).
					AddRow("adaptive_hash_searches", "adaptive_hash_index", "status_counter", "AHI searches", 7).
					AddRow("log_lsn_checkpoint_age", "log", "value", "Checkpoint age", 12).
					AddRow("log_lsn_current", "log", "value", "Current LSN", 99)
			},
			expected: []string{
				"mysql_innodb_metrics_buffer_flush_neighbor_batches_total",
				"mysql_innodb_metrics_buffer_flush_neighbor_pages_total",
				"mysql_innodb_metrics_purge_invocations_total",
				"mysql_innodb_metrics_transactions_read_write_committed_total",
				"mysql_innodb_metrics_adaptive_hash_searches_total",
				"mysql_info_schema_innodb_metrics_log_log_lsn_checkpoint_age",
			},
		},
		{
			// MySQL 5.7 keeps the redo rows under "recovery" and reports
			// log_lsn_checkpoint_age as a counter.
			name: "MySQL 5.7",
			rows: func() *sqlmock.Rows {
				return sqlmock.NewRows(columns).
					AddRow("buffer_flush_neighbor", "buffer", "set_member", "Neighbor flush batches", 2).
					AddRow("purge_invoked", "purge", "counter", "Purge invocations", 5).
					AddRow("trx_rw_commits", "transaction", "counter", "Read-write commits", 3).
					AddRow("log_lsn_checkpoint_age", "recovery", "counter", "Checkpoint age", 12).
					AddRow("log_lsn_current", "recovery", "value", "Current LSN", 99)
			},
			expected: []string{
				"mysql_innodb_metrics_buffer_flush_neighbor_batches_total",
				"mysql_innodb_metrics_purge_invocations_total",
				"mysql_info_schema_innodb_metrics_recovery_log_lsn_checkpoint_age",
				"mysql_info_schema_innodb_metrics_recovery_log_lsn_checkpoint_age_total",
			},
		},
		{
			// A synthetic layout standing in for a future release that reuses
			// one of the alias source names under a second subsystem. Keying
			// stableInnodbMetrics by subsystem is what keeps this from emitting
			// mysql_innodb_metrics_purge_invocations_total twice, which would
			// fail Gather() and drop the family from the endpoint.
			name: "one name under two subsystems",
			rows: func() *sqlmock.Rows {
				return sqlmock.NewRows(columns).
					AddRow("purge_invoked", "purge", "counter", "Purge invocations", 5).
					AddRow("purge_invoked", "purge_extra", "counter", "Purge invocations", 7)
			},
			expected: []string{
				"mysql_innodb_metrics_purge_invocations_total",
				"mysql_info_schema_innodb_metrics_purge_purge_invoked_total",
				"mysql_info_schema_innodb_metrics_purge_extra_purge_invoked_total",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("error opening a stub database connection: %s", err)
			}
			defer db.Close()

			mock.ExpectQuery(sanitizeQuery(infoSchemaInnodbMetricsEnabledColumnQuery)).
				WillReturnRows(sqlmock.NewRows([]string{"COLUMN_NAME"}).AddRow("STATUS"))
			query := fmt.Sprintf(infoSchemaInnodbMetricsQuery, "status", "enabled")
			mock.ExpectQuery(sanitizeQuery(query)).WillReturnRows(tc.rows())

			registry := prometheus.NewRegistry()
			registry.MustRegister(scraperCollector{
				t:       t,
				ctx:     t.Context(),
				scraper: ScrapeInnodbMetrics{},
				inst:    &instance{db: db},
			})

			families, err := registry.Gather()
			if err != nil {
				t.Fatalf("gathering innodb_metrics: %v", err)
			}

			exported := make(map[string]bool, len(families))
			for _, family := range families {
				exported[family.GetName()] = true
			}
			for _, name := range tc.expected {
				if !exported[name] {
					t.Errorf("metric family %s was not exported", name)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

func TestScrapeInnodbMetricsStableAliasSkipsNegative(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery(sanitizeQuery(infoSchemaInnodbMetricsEnabledColumnQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"COLUMN_NAME"}).AddRow("STATUS"))
	rows := sqlmock.NewRows([]string{"name", "subsystem", "type", "comment", "count"}).
		AddRow("purge_invoked", "purge", "counter", "Purge invocations", -1)
	query := fmt.Sprintf(infoSchemaInnodbMetricsQuery, "status", "enabled")
	mock.ExpectQuery(sanitizeQuery(query)).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		defer close(ch)
		if scrapeErr := (ScrapeInnodbMetrics{}).Scrape(t.Context(), &instance{db: db}, ch, promslog.NewNopLogger()); scrapeErr != nil {
			t.Errorf("error calling function on test: %s", scrapeErr)
		}
	}()

	collected := metricsByName(t, ch)

	// A cumulative counter cannot be negative, so neither the stable alias nor
	// the generic counter may carry the sentinel.
	assertNoMetric(t, collected,
		"mysql_innodb_metrics_purge_invocations_total",
		"mysql_info_schema_innodb_metrics_purge_purge_invoked_total",
	)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}

func TestScrapeInnodbMetricsGaugeOverrideKeepsNegativeGauge(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery(sanitizeQuery(infoSchemaInnodbMetricsEnabledColumnQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"COLUMN_NAME"}).AddRow("STATUS"))
	// Only counters are dropped for a negative value: an LSN position reported
	// as a value is a legitimate sample and dashboards still need the gauge.
	rows := sqlmock.NewRows([]string{"name", "subsystem", "type", "comment", "count"}).
		AddRow("log_lsn_current", "log", "value", "Current LSN", -1)
	query := fmt.Sprintf(infoSchemaInnodbMetricsQuery, "status", "enabled")
	mock.ExpectQuery(sanitizeQuery(query)).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		defer close(ch)
		if scrapeErr := (ScrapeInnodbMetrics{}).Scrape(t.Context(), &instance{db: db}, ch, promslog.NewNopLogger()); scrapeErr != nil {
			t.Errorf("error calling function on test: %s", scrapeErr)
		}
	}()

	collected := metricsByName(t, ch)

	assertMetric(t, collected, "mysql_info_schema_innodb_metrics_log_log_lsn_current", -1, dto.MetricType_GAUGE)
	assertNoMetric(t, collected, "mysql_info_schema_innodb_metrics_log_log_lsn_current_total")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
