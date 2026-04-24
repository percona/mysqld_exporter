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
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alecthomas/kingpin/v2"
	"github.com/blang/semver/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func TestPScrapeProcesslistQuerySelection(t *testing.T) {
	if _, err := kingpin.CommandLine.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name              string
		flavor            string
		version           semver.Version
		perfSchemaEnabled bool
		expectedSchema    string
	}{
		{"MySQL 8.0.22 + PS on -> perf_schema", FlavorMySQL, semver.MustParse("8.0.22"), true, processlistPerfSchema},
		{"MySQL 8.0.30 + PS on -> perf_schema", FlavorMySQL, semver.MustParse("8.0.30"), true, processlistPerfSchema},
		{"MySQL 5.7.39 + PS on -> perf_schema", FlavorMySQL, semver.MustParse("5.7.39"), true, processlistPerfSchema},
		{"MySQL 8.0.22 + PS off -> info_schema", FlavorMySQL, semver.MustParse("8.0.22"), false, processlistInfoSchema},
		{"MySQL 5.7.39 + PS off -> info_schema", FlavorMySQL, semver.MustParse("5.7.39"), false, processlistInfoSchema},
		{"MySQL 8.0.21 -> info_schema", FlavorMySQL, semver.MustParse("8.0.21"), true, processlistInfoSchema},
		{"MySQL 5.7.38 -> info_schema", FlavorMySQL, semver.MustParse("5.7.38"), true, processlistInfoSchema},
		{"MySQL 8.0.0 -> info_schema", FlavorMySQL, semver.MustParse("8.0.0"), true, processlistInfoSchema},
		{"MySQL 5.6.50 -> info_schema", FlavorMySQL, semver.MustParse("5.6.50"), true, processlistInfoSchema},
		{"MariaDB 10.11.0 -> info_schema", FlavorMariaDB, semver.MustParse("10.11.0"), true, processlistInfoSchema},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("error opening a stub database connection: %s", err)
			}
			defer db.Close()

			inst := &instance{
				db:                         db,
				flavor:                     tc.flavor,
				version:                    tc.version,
				isPerformanceSchemaEnabled: tc.perfSchemaEnabled,
			}

			expectedSQL := fmt.Sprintf(pInfoSchemaProcesslistQuery, tc.expectedSchema, 0)
			columns := []string{"command", "state", "count", "time"}
			mock.ExpectQuery(sanitizeQuery(expectedSQL)).
				WillReturnRows(sqlmock.NewRows(columns))

			ch := make(chan prometheus.Metric)
			go func() {
				if err := (PScrapeProcesslist{}).Scrape(context.Background(), inst, ch, promslog.NewNopLogger()); err != nil {
					t.Errorf("error calling Scrape: %s", err)
				}
				close(ch)
			}()
			for range ch {
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %s", err)
			}
		})
	}
}
