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

package collector

import (
	"context"
	"reflect"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

// The mock returns max_int verbatim, so this only covers turning rows into
// metrics. The unsigned detection lives in the SQL itself and is covered by
// TestScrapeAutoIncrementColumnsMaxValue against a real server.
func TestScrapeAutoIncrementColumns(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"table_schema", "table_name", "column_name", "auto_increment", "max_int"}).
		AddRow("test", "signed", "id", 20_000, 32_767).
		AddRow("test", "unsigned", "id", 47_000, 65_535)
	mock.ExpectQuery(infoSchemaAutoIncrementQuery).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		if err := (ScrapeAutoIncrementColumns{}).Scrape(
			context.Background(),
			&instance{db: db},
			ch,
			promslog.NewNopLogger(),
		); err != nil {
			t.Errorf("error calling function on test: %s", err)
		}
		close(ch)
	}()

	expected := []MetricResult{
		{labels: labelMap{"schema": "test", "table": "signed", "column": "id"}, value: 20_000, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "signed", "column": "id"}, value: 32_767, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "unsigned", "column": "id"}, value: 47_000, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "unsigned", "column": "id"}, value: 65_535, metricType: dto.MetricType_GAUGE},
	}
	for i, want := range expected {
		metric, ok := <-ch
		if !ok {
			t.Fatalf("channel closed after %d metrics, want %d", i, len(expected))
		}
		if got := readMetric(metric); !reflect.DeepEqual(got, want) {
			t.Errorf("metric %d mismatch:\ngot  %#v\nwant %#v", i, got, want)
		}
	}
	if extra, ok := <-ch; ok {
		t.Errorf("unexpected extra metric: %#v", readMetric(extra))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %s", err)
	}
}
