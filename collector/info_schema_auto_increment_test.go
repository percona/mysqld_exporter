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
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

func TestInfoSchemaAutoIncrementQueryDetectsUnsignedWithTrailingAttributes(t *testing.T) {
	if !strings.Contains(infoSchemaAutoIncrementQuery, "column_type like '%unsigned%'") {
		t.Fatalf("query must detect unsigned columns regardless of trailing attributes")
	}
}

func TestScrapeAutoIncrementColumns(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"table_schema", "table_name", "column_name", "auto_increment", "max_int"}).
		AddRow("test", "signed", "id", 20_000, 32_767).
		AddRow("test", "unsigned", "id", 47_000, 65_535).
		AddRow("test", "unsigned_zerofill", "id", 47_000, 65_535).
		AddRow("test", "display_width", "id", 20_000, 32_767)
	mock.ExpectQuery(infoSchemaAutoIncrementQuery).WillReturnRows(rows)

	ch := make(chan prometheus.Metric, 8)
	if err := (ScrapeAutoIncrementColumns{}).Scrape(
		context.Background(),
		&instance{db: db},
		ch,
		promslog.NewNopLogger(),
	); err != nil {
		t.Fatalf("scrape failed: %s", err)
	}

	expected := []MetricResult{
		{labels: labelMap{"schema": "test", "table": "signed", "column": "id"}, value: 20_000, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "signed", "column": "id"}, value: 32_767, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "unsigned", "column": "id"}, value: 47_000, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "unsigned", "column": "id"}, value: 65_535, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "unsigned_zerofill", "column": "id"}, value: 47_000, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "unsigned_zerofill", "column": "id"}, value: 65_535, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "display_width", "column": "id"}, value: 20_000, metricType: dto.MetricType_GAUGE},
		{labels: labelMap{"schema": "test", "table": "display_width", "column": "id"}, value: 32_767, metricType: dto.MetricType_GAUGE},
	}
	for i, want := range expected {
		if got := readMetric(<-ch); !reflect.DeepEqual(got, want) {
			t.Errorf("metric %d mismatch:\ngot  %#v\nwant %#v", i, got, want)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet SQL expectations: %s", err)
	}

	const alertThreshold = 90
	ratio := 47_000 * 100.0 / 65_535
	if ratio >= alertThreshold {
		t.Fatalf("unsigned zerofill usage ratio %.1f unexpectedly reaches alert threshold", ratio)
	}
}
