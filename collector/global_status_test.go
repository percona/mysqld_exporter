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
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/smartystreets/goconvey/convey"
)

func TestScrapeGlobalStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()
	inst := &instance{db: db}

	columns := []string{"Variable_name", "Value"}
	rows := sqlmock.NewRows(columns).
		AddRow("Com_alter_db", "1").
		AddRow("Com_show_status", "2").
		AddRow("Com_select", "3").
		AddRow("Connection_errors_internal", "4").
		AddRow("Handler_commit", "5").
		AddRow("Innodb_buffer_pool_pages_data", "6").
		AddRow("Innodb_buffer_pool_pages_flushed", "7").
		AddRow("Innodb_buffer_pool_pages_dirty", "7").
		AddRow("Innodb_buffer_pool_pages_free", "8").
		AddRow("Innodb_buffer_pool_pages_misc", "9").
		AddRow("Innodb_buffer_pool_pages_old", "10").
		AddRow("Innodb_buffer_pool_pages_total", "11").
		AddRow("Innodb_buffer_pool_pages_lru_flushed", "13").
		AddRow("Innodb_buffer_pool_pages_made_not_young", "14").
		AddRow("Innodb_buffer_pool_pages_made_young", "15").
		AddRow("Innodb_rows_read", "8").
		AddRow("Performance_schema_users_lost", "9").
		AddRow("Slave_running", "OFF").
		AddRow("Ssl_version", "").
		AddRow("Uptime", "10").
		AddRow("validate_password.dictionary_file_words_count", "11").
		AddRow("wsrep_cluster_status", "Primary").
		AddRow("wsrep_local_state_uuid", "6c06e583-686f-11e6-b9e3-8336ad58138c").
		AddRow("wsrep_cluster_state_uuid", "6c06e583-686f-11e6-b9e3-8336ad58138c").
		AddRow("wsrep_provider_version", "3.16(r5c765eb)").
		AddRow("wsrep_evs_repl_latency", "0.000227664/0.00034135/0.000544298/6.03708e-05/212")
	mock.ExpectQuery(sanitizeQuery(globalStatusQuery)).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		if err = (ScrapeGlobalStatus{}).Scrape(context.Background(), inst, ch, promslog.NewNopLogger()); err != nil {
			t.Errorf("error calling function on test: %s", err)
		}
		close(ch)
	}()

	counterExpected := []MetricResult{
		{labels: labelMap{"command": "alter_db"}, value: 1, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"command": "show_status"}, value: 2, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"command": "select"}, value: 3, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"error": "internal"}, value: 4, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"handler": "commit"}, value: 5, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"state": "data"}, value: 6, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"operation": "flushed"}, value: 7, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{}, value: 7, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"state": "free"}, value: 8, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"state": "misc"}, value: 9, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"state": "old"}, value: 10, metricType: dto.MetricType_GAUGE},
		//{labels: labelMap{"state": "total_pages"}, value: 11, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"operation": "lru_flushed"}, value: 13, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"operation": "made_not_young"}, value: 14, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"operation": "made_young"}, value: 15, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"operation": "read"}, value: 8, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{"instrumentation": "users_lost"}, value: 9, metricType: dto.MetricType_COUNTER},
		{labels: labelMap{}, value: 0, metricType: dto.MetricType_UNTYPED},
		{labels: labelMap{}, value: 10, metricType: dto.MetricType_UNTYPED},
		{labels: labelMap{}, value: 11, metricType: dto.MetricType_UNTYPED},
		{labels: labelMap{}, value: 1, metricType: dto.MetricType_UNTYPED},
		{labels: labelMap{"wsrep_local_state_uuid": "6c06e583-686f-11e6-b9e3-8336ad58138c", "wsrep_cluster_state_uuid": "6c06e583-686f-11e6-b9e3-8336ad58138c", "wsrep_provider_version": "3.16(r5c765eb)"}, value: 1, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{}, value: 0.000227664, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{}, value: 0.00034135, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{}, value: 0.000544298, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{}, value: 6.03708e-05, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{}, value: 212, metricType: dto.MetricType_GAUGE},
	}
	convey.Convey("Metrics comparison", t, func() {
		for _, expect := range counterExpected {
			got := readMetric(<-ch)
			convey.So(got, convey.ShouldResemble, expect)
		}
	})

	// Ensure all SQL queries were executed
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled exceptions: %s", err)
	}
}

// The redo log aggregation runs on keys that have already been through
// validPrometheusName, so it is driven here with the capitalisation a real
// server reports. Without that lowercasing every case in observe() would miss
// and all canonical and compatibility redo metrics would silently disappear.
func TestScrapeGlobalStatusInnodbRedoAliases(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()
	inst := &instance{db: db}

	rows := sqlmock.NewRows([]string{"Variable_name", "Value"}).
		AddRow("Innodb_redo_log_current_lsn", "1500").
		AddRow("Innodb_redo_log_checkpoint_lsn", "1000").
		AddRow("Innodb_redo_log_flushed_to_disk_lsn", "1400").
		AddRow("Innodb_redo_log_capacity_resized", "2000").
		AddRow("Innodb_os_log_written", "4096")
	mock.ExpectQuery(sanitizeQuery(globalStatusQuery)).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		defer close(ch)
		if scrapeErr := (ScrapeGlobalStatus{}).Scrape(context.Background(), inst, ch, promslog.NewNopLogger()); scrapeErr != nil {
			t.Errorf("error calling function on test: %s", scrapeErr)
		}
	}()

	collected := metricsByName(t, ch)

	assertMetric(t, collected, "mysql_innodb_redo_log_current_lsn", 1500, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_lsn", 1000, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_bytes", 500, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_flushed_lsn", 1400, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_ratio", 0.25, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_capacity_bytes", 2000, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_written_bytes_total", 4096, dto.MetricType_COUNTER)

	assertMetric(t, collected, "mysql_global_status_innodb_lsn_current", 1500, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_global_status_innodb_lsn_last_checkpoint", 1000, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_global_status_innodb_lsn_flushed", 1400, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_global_status_innodb_checkpoint_age", 500, dto.MetricType_GAUGE)

	// The rows themselves keep their generic series alongside the aliases.
	assertMetric(t, collected, "mysql_global_status_innodb_redo_log_current_lsn", 1500, dto.MetricType_UNTYPED)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled exceptions: %s", err)
	}
}
