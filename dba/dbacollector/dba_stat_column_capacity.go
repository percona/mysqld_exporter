package dbacollector

import (
	"context"
	"database/sql"

	"github.com/go-kit/log"
	cl "github.com/a-korotich/mysqld_exporter/collector"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	statColumnCapacityQuery = `
		SELECT
		   db_name table_schema,
		   table_name,
		   column_name,
		   ratio capacity
		FROM dba.stat_column_capacity
`)

var (
	globalStatColumnCapacityDesc = prometheus.NewDesc(
		prometheus.BuildFQName(cl.Namespace, "stat_column_capacity"),
		"The current capacity of intager columns.",
		[]string{"schema", "table", "column"}, nil,
	)
)

type ScrapeStatColumnCapacityColumns struct{}

// Name of the Scraper. Should be unique.
func (ScrapeStatColumnCapacityColumns) Name() string {
	return "stat_column_capacity"
}

// Help describes the role of the Scraper.
func (ScrapeStatColumnCapacityColumns) Help() string {
	return "Collect data from dba.stat_column_capacity"
}

// Version of MySQL from which scraper is available.
func (ScrapeStatColumnCapacityColumns) Version() float64 {
	return 5.1
}

// Scrape collects data from database connection and sends it over channel as prometheus metric.
func (ScrapeStatColumnCapacityColumns) Scrape(ctx context.Context, db *sql.DB, ch chan<- prometheus.Metric, logger log.Logger) error {
	columnCapacityRows, err := db.QueryContext(ctx, statColumnCapacityQuery)
	if err != nil {
		return err
	}
	defer columnCapacityRows.Close()

	var (
		schema, table, column string
		value            float64
	)

	for columnCapacityRows.Next() {
		if err := columnCapacityRows.Scan(
			&schema, &table, &column, &value,
		); err != nil {
			return err
		}
		ch <- prometheus.MustNewConstMetric(
			globalStatColumnCapacityDesc, prometheus.GaugeValue, value,
			schema, table, column,
		)
	}
	return nil
}

var _ cl.Scraper = ScrapeStatColumnCapacityColumns{}