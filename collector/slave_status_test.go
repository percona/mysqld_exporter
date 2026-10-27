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
			name:    "MySQL 8.0.22+ uses SHOW REPLICA STATUS only",
			flavor:  FlavorMySQL,
			version: "8.0.36",
			steps:   []step{{query: "SHOW REPLICA STATUS"}},
		},
		{
			name:    "MySQL 8.4 uses SHOW REPLICA STATUS only",
			flavor:  FlavorMySQL,
			version: "8.4.3",
			steps:   []step{{query: "SHOW REPLICA STATUS"}},
		},
		{
			name:    "MySQL before 8.0.22 uses SHOW SLAVE STATUS only",
			flavor:  FlavorMySQL,
			version: "5.7.44",
			steps:   []step{{query: "SHOW SLAVE STATUS"}},
		},
		{
			name:    "syntax error on the preferred statement falls back to probing",
			flavor:  FlavorMySQL,
			version: "8.0.36",
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
