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
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/blang/semver/v4"
	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/smartystreets/goconvey/convey"
)

func TestScrapeSlaveStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()
	inst := &instance{db: db}

	columns := []string{"Master_Host", "Read_Master_Log_Pos", "Slave_IO_Running", "Slave_SQL_Running", "Seconds_Behind_Master"}
	rows := sqlmock.NewRows(columns).
		AddRow("127.0.0.1", "1", "Connecting", "Yes", "2")
	mock.ExpectQuery(sanitizeQuery("SHOW SLAVE STATUS")).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		if err = (ScrapeSlaveStatus{}).Scrape(context.Background(), inst, ch, promslog.NewNopLogger()); err != nil {
			t.Errorf("error calling function on test: %s", err)
		}
		close(ch)
	}()

	counterExpected := []MetricResult{
		{labels: labelMap{"channel_name": "", "connection_name": "", "master_host": "127.0.0.1", "master_uuid": ""}, value: 1, metricType: dto.MetricType_UNTYPED},
		{labels: labelMap{"channel_name": "", "connection_name": "", "master_host": "127.0.0.1", "master_uuid": ""}, value: 0, metricType: dto.MetricType_UNTYPED},
		{labels: labelMap{"channel_name": "", "connection_name": "", "master_host": "127.0.0.1", "master_uuid": ""}, value: 1, metricType: dto.MetricType_UNTYPED},
		{labels: labelMap{"channel_name": "", "connection_name": "", "master_host": "127.0.0.1", "master_uuid": ""}, value: 2, metricType: dto.MetricType_UNTYPED},
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

func TestQuerySlaveStatusStatements(t *testing.T) {
	parseErr := &mysql.MySQLError{Number: erParseError, Message: "You have an error in your SQL syntax"}
	accessDenied := &mysql.MySQLError{Number: 1227, Message: "Access denied"}

	type step struct {
		query string
		err   error
	}
	tests := []struct {
		name    string
		flavor  string
		version string
		steps   []step
		wantErr bool
	}{
		{
			name:    "MariaDB uses SHOW ALL SLAVES STATUS only",
			flavor:  FlavorMariaDB,
			version: "10.11.9",
			steps:   []step{{query: "SHOW ALL SLAVES STATUS"}},
		},
		{
			name:    "MySQL 8.0.22 to 8.3 keeps SHOW SLAVE STATUS to preserve metric names",
			flavor:  FlavorMySQL,
			version: "8.0.36",
			steps:   []step{{query: "SHOW SLAVE STATUS"}},
		},
		{
			name:    "MySQL 8.3 keeps SHOW SLAVE STATUS",
			flavor:  FlavorMySQL,
			version: "8.3.0",
			steps:   []step{{query: "SHOW SLAVE STATUS"}},
		},
		{
			name:    "MySQL 8.4 uses SHOW REPLICA STATUS only",
			flavor:  FlavorMySQL,
			version: "8.4.3",
			steps:   []step{{query: "SHOW REPLICA STATUS"}},
		},
		{
			name:    "MySQL 5.7 uses SHOW SLAVE STATUS only",
			flavor:  FlavorMySQL,
			version: "5.7.44",
			steps:   []step{{query: "SHOW SLAVE STATUS"}},
		},
		{
			name:    "syntax error on the preferred statement falls back to probing",
			flavor:  FlavorMySQL,
			version: "8.4.3",
			steps: []step{
				{query: "SHOW REPLICA STATUS", err: parseErr},
				{query: "SHOW ALL SLAVES STATUS", err: parseErr},
				{query: "SHOW ALL SLAVES STATUS NONBLOCKING", err: parseErr},
				{query: "SHOW ALL SLAVES STATUS NOLOCK", err: parseErr},
				{query: "SHOW SLAVE STATUS"},
			},
		},
		{
			name:    "non-syntax errors are returned without probing",
			flavor:  FlavorMariaDB,
			version: "10.11.9",
			steps:   []step{{query: "SHOW ALL SLAVES STATUS", err: accessDenied}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			if err != nil {
				t.Fatalf("error opening a stub database connection: %s", err)
			}
			defer db.Close()
			inst := &instance{db: db, flavor: tt.flavor, version: semver.MustParse(tt.version)}

			for _, s := range tt.steps {
				if s.err != nil {
					mock.ExpectQuery(s.query).WillReturnError(s.err)
				} else {
					mock.ExpectQuery(s.query).WillReturnRows(sqlmock.NewRows([]string{"Master_Host"}))
				}
			}

			rows, err := querySlaveStatus(context.Background(), inst)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				rows.Close()
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}

// Metric names are derived from column names, so the statement chosen per version must
// keep the series that existed before flavor-based selection was introduced.
func TestScrapeSlaveStatusMetricNames(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		query     string
		columns   []string
		wantNames []string
	}{
		{
			name:      "MySQL 8.0 keeps legacy slave_* metric names",
			version:   "8.0.36",
			query:     "SHOW SLAVE STATUS",
			columns:   []string{"Master_Host", "Slave_IO_Running", "Slave_SQL_Running", "Seconds_Behind_Master"},
			wantNames: []string{"mysql_slave_status_slave_io_running", "mysql_slave_status_slave_sql_running", "mysql_slave_status_seconds_behind_master"},
		},
		{
			name:      "MySQL 8.4 keeps replica_* metric names",
			version:   "8.4.3",
			query:     "SHOW REPLICA STATUS",
			columns:   []string{"Source_Host", "Replica_IO_Running", "Replica_SQL_Running", "Seconds_Behind_Source"},
			wantNames: []string{"mysql_slave_status_replica_io_running", "mysql_slave_status_replica_sql_running", "mysql_slave_status_seconds_behind_source"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
			if err != nil {
				t.Fatalf("error opening a stub database connection: %s", err)
			}
			defer db.Close()
			inst := &instance{db: db, flavor: FlavorMySQL, version: semver.MustParse(tt.version)}

			mock.ExpectQuery(tt.query).WillReturnRows(sqlmock.NewRows(tt.columns).AddRow("127.0.0.1", "Yes", "Yes", "0"))

			ch := make(chan prometheus.Metric)
			go func() {
				if err := (ScrapeSlaveStatus{}).Scrape(context.Background(), inst, ch, promslog.NewNopLogger()); err != nil {
					t.Errorf("error calling function on test: %s", err)
				}
				close(ch)
			}()

			var got []string
			for m := range ch {
				got = append(got, m.Desc().String())
			}
			for _, want := range tt.wantNames {
				found := false
				for _, desc := range got {
					if strings.Contains(desc, `fqName: "`+want+`"`) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("metric %s not emitted; got %v", want, got)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("there were unfulfilled expectations: %s", err)
			}
		})
	}
}
