// Copyright 2018 The Prometheus Authors, 2023 Percona LLC
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
	"os"
	"path/filepath"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alecthomas/kingpin/v2"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/smartystreets/goconvey/convey"
)

const customQueryCounter = `
experiment_garden:
  query: "SELECT fruit, amount FROM experiment.garden;"
  metrics:
    - fruit:
        usage: "LABEL"
        description: "Fruit names"
    - amount:
        usage: "COUNTER"
        description: "Amount fruits in the garden"

`

func TestScrapeCustomQueriesCounter(t *testing.T) {
	convey.Convey("Custom queries counter", t, func() {
		tmpFileName := createTmpFile(t, string(HR), customQueryCounter)
		defer os.Remove(tmpFileName)

		_, err := kingpin.CommandLine.Parse([]string{
			"--collect.custom_query.hr.directory", filepath.Dir(tmpFileName),
		})
		if err != nil {
			t.Fatal(err)
		}

		defer os.Remove(*collectCustomQueryHrDirectory)

		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("error opening a stub database connection: %s", err)
		}
		defer db.Close()

		columns := []string{"fruit", "amount"}
		rows := sqlmock.NewRows(columns).
			AddRow("apple", "10").
			AddRow("cherry", "35").
			AddRow("pear", "42").
			AddRow("plumb", "80")
		mock.ExpectQuery(sanitizeQuery("SELECT fruit, amount FROM experiment.garden;")).WillReturnRows(rows)

		ch := make(chan prometheus.Metric)
		go func() {
			instance := &instance{db: db}
			if err = (ScrapeCustomQuery{Resolution: HR}).Scrape(context.Background(), instance, ch, promslog.NewNopLogger()); err != nil {
				t.Errorf("error calling function on test: %s", err)
			}
			close(ch)
		}()

		counterExpected := []MetricResult{
			{labels: labelMap{"fruit": "apple"}, value: 10, metricType: dto.MetricType_COUNTER},
			{labels: labelMap{"fruit": "cherry"}, value: 35, metricType: dto.MetricType_COUNTER},
			{labels: labelMap{"fruit": "pear"}, value: 42, metricType: dto.MetricType_COUNTER},
			{labels: labelMap{"fruit": "plumb"}, value: 80, metricType: dto.MetricType_COUNTER},
		}
		convey.Convey("Metrics should be resemble", func() {
			for _, expect := range counterExpected {
				got := readMetric(<-ch)
				convey.So(got, convey.ShouldResemble, expect)
			}
		})

		// Ensure all SQL queries were executed
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expections: %s", err)
		}
	})
}

const customQueryDuration = `
experiment_garden:
  query: "SELECT fruit, ripen FROM experiment.garden;"
  metrics:
    - fruit:
        usage: "LABEL"
        description: "Fruit names"
    - amount:
        usage: "DURATION"
        description: "Time to become ripe."

`

func TestScrapeCustomQueriesDuration(t *testing.T) {
	convey.Convey("Custom queries duration", t, func() {
		tmpFileName := createTmpFile(t, string(HR), customQueryDuration)
		defer os.Remove(tmpFileName)

		*collectCustomQueryHrDirectory = filepath.Dir(tmpFileName)
		defer os.Remove(*collectCustomQueryHrDirectory)

		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("error opening a stub database connection: %s", err)
		}
		defer db.Close()

		columns := []string{"fruit", "amount"}
		rows := sqlmock.NewRows(columns).
			AddRow("apple", "2592000000").
			AddRow("cherry", "2692000000").
			AddRow("pear", "2792000000").
			AddRow("plumb", "2892000000")
		mock.ExpectQuery(sanitizeQuery("SELECT fruit, ripen FROM experiment.garden;")).WillReturnRows(rows)

		ch := make(chan prometheus.Metric)
		go func() {
			instance := &instance{db: db}
			if err = (ScrapeCustomQuery{Resolution: HR}).Scrape(context.Background(), instance, ch, promslog.NewNopLogger()); err != nil {
				t.Errorf("error calling function on test: %s", err)
			}
			close(ch)
		}()

		counterExpected := []MetricResult{
			{labels: labelMap{"fruit": "apple"}, value: 2592000000, metricType: dto.MetricType_GAUGE},
			{labels: labelMap{"fruit": "cherry"}, value: 2692000000, metricType: dto.MetricType_GAUGE},
			{labels: labelMap{"fruit": "pear"}, value: 2792000000, metricType: dto.MetricType_GAUGE},
			{labels: labelMap{"fruit": "plumb"}, value: 2892000000, metricType: dto.MetricType_GAUGE},
		}
		convey.Convey("Metrics should be resemble", func() {
			for _, expect := range counterExpected {
				got := readMetric(<-ch)
				convey.So(got, convey.ShouldResemble, expect)
			}
		})

		// Ensure all SQL queries were executed
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expections: %s", err)
		}
	})
}

const customQueryNoDb = `
experiment_garden:
  query: "SELECT fruit, ripen FROM non_existed_experiment.garden;"
  metrics:
    - fruit:
        usage: "LABEL"
        description: "Fruit names"
    - amount:
        usage: "DURATION"
        description: "Time to become ripe."

`

func TestScrapeCustomQueriesDbError(t *testing.T) {
	convey.Convey("Custom queries db error", t, func() {
		tmpFileName := createTmpFile(t, string(HR), customQueryNoDb)
		defer os.Remove(tmpFileName)

		*collectCustomQueryHrDirectory = filepath.Dir(tmpFileName)
		defer os.Remove(*collectCustomQueryHrDirectory)

		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("error opening a stub database connection: %s", err)
		}
		defer db.Close()

		expectedError := fmt.Errorf("ERROR 1049 (42000): Unknown database 'non_existed_experiment'")
		mock.ExpectQuery(sanitizeQuery("SELECT fruit, ripen FROM non_existed_experiment.garden;")).WillReturnError(expectedError)

		ch := make(chan prometheus.Metric)

		expectedErr := "experiment_garden:error running query on database: experiment_garden, ERROR 1049 (42000): Unknown database 'non_existed_experiment'"
		convey.Convey("Should raise error ", func() {
			instance := &instance{db: db}
			err = (ScrapeCustomQuery{Resolution: HR}).Scrape(context.Background(), instance, ch, promslog.NewNopLogger())
			convey.So(err, convey.ShouldBeError, expectedErr)
		})
		close(ch)
	})
}

const customQueryIncorrectYaml = `
{"foo": "bar"}
`

func TestScrapeCustomQueriesIncorrectYaml(t *testing.T) {
	convey.Convey("Custom queries incorrect yaml", t, func() {
		tmpFileName := createTmpFile(t, string(HR), customQueryIncorrectYaml)
		defer os.Remove(tmpFileName)

		*collectCustomQueryHrDirectory = filepath.Dir(tmpFileName)
		defer os.Remove(*collectCustomQueryHrDirectory)

		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("error opening a stub database connection: %s", err)
		}
		defer db.Close()

		ch := make(chan prometheus.Metric)

		convey.Convey("Should raise error ", func() {
			instance := &instance{db: db}
			err = (ScrapeCustomQuery{Resolution: HR}).Scrape(context.Background(), instance, ch, promslog.NewNopLogger())
			convey.So(err, convey.ShouldBeError, "failed to add custom queries:incorrect yaml format for bar")
		})
		close(ch)
	})
}

func TestScrapeCustomQueriesNoFile(t *testing.T) {
	convey.Convey("Passed as a custom queries non-existing file or path", t, func() {
		*collectCustomQueryHrDirectory = "/wrong/path"

		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("error opening a stub database connection: %s", err)
		}
		ch := make(chan prometheus.Metric)
		instance := &instance{db: db}
		err = (ScrapeCustomQuery{Resolution: HR}).Scrape(context.Background(), instance, ch, promslog.NewNopLogger())
		close(ch)
		convey.So(err, convey.ShouldBeError, "failed to read directory '/wrong/path' for custom query, error: open /wrong/path: no such file or directory")
	})
}

const customQueryReplicationGroupWorker = `
mysql_perf_schema_replication_group_worker:
  query: "SELECT channel_name, worker_id, IO_thread, SQL_thread, transport_time_seconds FROM replication_worker_view"
  metrics:
    - channel_name:
        usage: "LABEL"
        description: "The replication channel."
    - worker_id:
        usage: "LABEL"
        description: "The worker thread ID. 0 for single-threaded replication; 1..N for parallel replication workers."
    - IO_thread:
        usage: "LABEL"
        description: "IO thread state."
    - SQL_thread:
        usage: "LABEL"
        description: "SQL thread state."
    - transport_time_seconds:
        usage: "GAUGE"
        description: "Transport time in seconds."
`

func TestScrapeCustomQueriesReplicationGroupWorkerParallelReplication(t *testing.T) {
	convey.Convey("Replication group worker with parallel replication", t, func() {
		tmpFileName := createTmpFile(t, string(HR), customQueryReplicationGroupWorker)
		defer os.Remove(tmpFileName)

		*collectCustomQueryHrDirectory = filepath.Dir(tmpFileName)
		defer os.Remove(*collectCustomQueryHrDirectory)

		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatalf("error opening a stub database connection: %s", err)
		}
		defer db.Close()

		// Simulate parallel replication: same channel_name, multiple worker_ids.
		columns := []string{"channel_name", "worker_id", "IO_thread", "SQL_thread", "transport_time_seconds"}
		rows := sqlmock.NewRows(columns).
			AddRow("default", "1", "ON", "ON", "0.5").
			AddRow("default", "2", "ON", "ON", "0.3").
			AddRow("default", "3", "ON", "ON", "0.7")
		mock.ExpectQuery(sanitizeQuery("SELECT channel_name, worker_id, IO_thread, SQL_thread, transport_time_seconds FROM replication_worker_view")).WillReturnRows(rows)

		ch := make(chan prometheus.Metric)
		go func() {
			instance := &instance{db: db}
			if err = (ScrapeCustomQuery{Resolution: HR}).Scrape(context.Background(), instance, ch, promslog.NewNopLogger()); err != nil {
				t.Errorf("error calling function on test: %s", err)
			}
			close(ch)
		}()

		metricsExpected := []MetricResult{
			{labels: labelMap{"channel_name": "default", "worker_id": "1", "IO_thread": "ON", "SQL_thread": "ON"}, value: 0.5, metricType: dto.MetricType_GAUGE},
			{labels: labelMap{"channel_name": "default", "worker_id": "2", "IO_thread": "ON", "SQL_thread": "ON"}, value: 0.3, metricType: dto.MetricType_GAUGE},
			{labels: labelMap{"channel_name": "default", "worker_id": "3", "IO_thread": "ON", "SQL_thread": "ON"}, value: 0.7, metricType: dto.MetricType_GAUGE},
		}
		convey.Convey("Each parallel worker produces a unique metric", func() {
			for _, expect := range metricsExpected {
				got := readMetric(<-ch)
				convey.So(got, convey.ShouldResemble, expect)
			}
		})

		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled expectations: %s", err)
		}
	})
}

func createTmpFile(t *testing.T, resolution, content string) string {
	// Create our Temp File
	tempDir := os.TempDir() + "/" + resolution
	err := os.MkdirAll(tempDir, os.ModePerm)
	if err != nil {
		t.Fatalf("Cannot create temporary directory: %s", err)
	}
	tmpFile, err := os.CreateTemp(tempDir, "custom_queries.*.yaml")
	if err != nil {
		t.Fatalf("Cannot create temporary file: %s", err)
	}

	// Example writing to the file
	_, err = tmpFile.Write([]byte(content))
	if err != nil {
		t.Fatalf("Failed to write to temporary file: %s", err)
	}
	return tmpFile.Name()
}
