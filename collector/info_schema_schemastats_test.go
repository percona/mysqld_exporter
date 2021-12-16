package collector

import (
	"context"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/smartystreets/goconvey/convey"
)

func TestScrapeSchemaStat(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()

	mock.ExpectQuery(sanitizeQuery(userstatCheckQuery)).WillReturnRows(sqlmock.NewRows([]string{"Variable_name", "Value"}).
		AddRow("userstat", "ON"))

	columns := []string{"TABLE_SCHEMA", "ROWS_READ", "ROWS_CHANGED", "ROWS_CHANGED_X_INDEXES"}
	rows := sqlmock.NewRows(columns).
		AddRow("mysql", 238, 0, 8).
		AddRow("default", 99, 1, 0)
	mock.ExpectQuery(sanitizeQuery(schemaStatQuery)).WillReturnRows(rows)

	ch := make(chan prometheus.Metric)
	go func() {
		if err = (ScrapeSchemaStat{}).Scrape(context.Background(), db, ch, log.NewNopLogger()); err != nil {
			t.Errorf("error calling function on test: %s", err)
		}
		close(ch)
	}()

	expected := []MetricResult{
		{labels: labelMap{"schema": "mysql"}, value: 238},
		{labels: labelMap{"schema": "mysql"}, value: 0},
		{labels: labelMap{"schema": "mysql"}, value: 8},
		{labels: labelMap{"schema": "default"}, value: 99},
		{labels: labelMap{"schema": "default"}, value: 1},
		{labels: labelMap{"schema": "default"}, value: 0},
	}
	convey.Convey("Metrics comparison", t, func() {
		for _, expect := range expected {
			got := readMetric(<-ch)
			convey.So(expect, convey.ShouldResemble, got)
		}
	})

	// Ensure all SQL queries were executed
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled exceptions: %s", err)
	}
}
