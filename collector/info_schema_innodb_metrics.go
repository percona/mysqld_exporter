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

// Scrape `information_schema.innodb_metrics`.

package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const infoSchemaInnodbMetricsEnabledColumnQuery = `
	SELECT
	    column_name
	  FROM information_schema.columns
	  WHERE table_schema = 'information_schema'
	    AND table_name = 'INNODB_METRICS'
	    AND column_name IN ('status', 'enabled')
	  LIMIT 1
	`

const infoSchemaInnodbMetricsQuery = `
		SELECT
		  name, subsystem, type, comment,
		  count
		  FROM information_schema.innodb_metrics
		  WHERE ` + "`%s` = '%s'"

// Metrics descriptors.
var (
	infoSchemaBufferPageReadTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, informationSchema, "innodb_metrics_buffer_page_read_total"),
		"Total number of buffer pages read total.",
		[]string{"type"}, nil,
	)
	infoSchemaBufferPageWrittenTotalDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, informationSchema, "innodb_metrics_buffer_page_written_total"),
		"Total number of buffer pages written total.",
		[]string{"type"}, nil,
	)
	infoSchemaBufferPoolPagesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, informationSchema, "innodb_metrics_buffer_pool_pages"),
		"Total number of buffer pool pages by state.",
		[]string{"state"}, nil,
	)
	infoSchemaBufferPoolPagesDirtyDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, informationSchema, "innodb_metrics_buffer_pool_dirty_pages"),
		"Total number of dirty pages in the buffer pool.",
		nil, nil,
	)
)

type stableInnodbMetric struct {
	name string
	help string
}

// stableInnodbMetrics provides a version-independent API for metrics used by
// dashboards. MySQL has changed the TYPE reported by INNODB_METRICS for some
// counters, which changes whether the generic collector appends "_total".
// Keep the generic metrics for compatibility and emit these stable aliases in
// addition.
var stableInnodbMetrics = map[string]stableInnodbMetric{
	"buffer_flush_neighbor": {
		name: "buffer_flush_neighbor_batches_total",
		help: "Total number of neighbor page flush batches.",
	},
	"buffer_flush_neighbor_total_pages": {
		name: "buffer_flush_neighbor_pages_total",
		help: "Total number of pages flushed by neighbor page flushing.",
	},
	"purge_invoked": {
		name: "purge_invocations_total",
		help: "Total number of times purge was invoked.",
	},
	"purge_upd_exist_or_extern_records": {
		name: "purge_updated_records_total",
		help: "Total number of updated records processed by purge.",
	},
	"purge_del_mark_records": {
		name: "purge_delete_marked_records_total",
		help: "Total number of delete-marked records processed by purge.",
	},
	"trx_rw_commits": {
		name: "transactions_read_write_committed_total",
		help: "Total number of committed read-write transactions.",
	},
	"adaptive_hash_rows_added": {
		name: "adaptive_hash_rows_added_total",
		help: "Total number of rows added to the adaptive hash index.",
	},
	"adaptive_hash_rows_removed": {
		name: "adaptive_hash_rows_removed_total",
		help: "Total number of rows removed from the adaptive hash index.",
	},
	"adaptive_hash_rows_updated": {
		name: "adaptive_hash_rows_updated_total",
		help: "Total number of rows updated in the adaptive hash index.",
	},
	"adaptive_hash_pages_added": {
		name: "adaptive_hash_pages_added_total",
		help: "Total number of pages added to the adaptive hash index.",
	},
	"adaptive_hash_searches": {
		name: "adaptive_hash_searches_total",
		help: "Total number of adaptive hash index searches.",
	},
	"adaptive_hash_searches_btree": {
		name: "adaptive_hash_btree_searches_total",
		help: "Total number of B-tree searches that bypassed the adaptive hash index.",
	},
}

// These values are positions or sizes rather than monotonically increasing
// event counters. Some MySQL versions report them as counters, but dashboards
// need their unsuffixed gauge names for max_over_time and direct arithmetic.
var innodbMetricGaugeOverrides = map[string]struct{}{
	"log/log_lsn_checkpoint_age":     {},
	"log/log_lsn_current":            {},
	"log/log_lsn_last_checkpoint":    {},
	"log/log_lsn_last_flush":         {},
	"log/log_max_modified_age_async": {},
}

// Regexp for matching metric aggregations.
var (
	bufferRE     = regexp.MustCompile(`^buffer_(pool_pages)_(.*)$`)
	bufferPageRE = regexp.MustCompile(`^buffer_page_(read|written)_(.*)$`)
)

// ScrapeInnodbMetrics collects from `information_schema.innodb_metrics`.
type ScrapeInnodbMetrics struct{}

// Name of the Scraper. Should be unique.
func (ScrapeInnodbMetrics) Name() string {
	return informationSchema + ".innodb_metrics"
}

// Help describes the role of the Scraper.
func (ScrapeInnodbMetrics) Help() string {
	return "Collect metrics from information_schema.innodb_metrics"
}

// Version of MySQL from which scraper is available.
func (ScrapeInnodbMetrics) Version() float64 {
	return 5.6
}

// Scrape collects data from database connection and sends it over channel as prometheus metric.
func (ScrapeInnodbMetrics) Scrape(ctx context.Context, instance *instance, ch chan<- prometheus.Metric, logger *slog.Logger) error {
	var enabledColumnName string
	var query string

	db := instance.getDB()
	err := db.QueryRowContext(ctx, infoSchemaInnodbMetricsEnabledColumnQuery).Scan(&enabledColumnName)
	if err != nil {
		return err
	}

	switch enabledColumnName {
	case "STATUS":
		query = fmt.Sprintf(infoSchemaInnodbMetricsQuery, "status", "enabled")
	case "ENABLED":
		query = fmt.Sprintf(infoSchemaInnodbMetricsQuery, "enabled", "1")
	default:
		return errors.New("Couldn't find column STATUS or ENABLED in innodb_metrics table.")
	}

	innodbMetricsRows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer innodbMetricsRows.Close()

	var (
		name, subsystem, metricType, comment string
		value                                float64
	)

	for innodbMetricsRows.Next() {
		if err := innodbMetricsRows.Scan(
			&name, &subsystem, &metricType, &comment, &value,
		); err != nil {
			return err
		}
		if stable, ok := stableInnodbMetrics[name]; ok && value >= 0 {
			ch <- prometheus.MustNewConstMetric(
				prometheus.NewDesc(
					prometheus.BuildFQName(namespace, "innodb_metrics", stable.name),
					stable.help, nil, nil,
				),
				prometheus.CounterValue,
				value,
			)
		}
		// Special handling of the "buffer_page_io" subsystem.
		if subsystem == "buffer_page_io" {
			match := bufferPageRE.FindStringSubmatch(name)
			if len(match) != 3 {
				logger.Warn("innodb_metrics subsystem buffer_page_io returned an invalid name", "name", name)
				continue
			}
			switch match[1] {
			case "read":
				ch <- prometheus.MustNewConstMetric(
					infoSchemaBufferPageReadTotalDesc, prometheus.CounterValue, value, match[2],
				)
			case "written":
				ch <- prometheus.MustNewConstMetric(
					infoSchemaBufferPageWrittenTotalDesc, prometheus.CounterValue, value, match[2],
				)
			}
			continue
		}
		if subsystem == "buffer" {
			match := bufferRE.FindStringSubmatch(name)
			// Many buffer subsystem metrics are not matched, fall through to generic metric.
			if match != nil {
				switch match[1] {
				case "pool_pages":
					switch match[2] {
					case "total":
						// Ignore total, it is an aggregation of the rest.
						continue
					case "dirty":
						// Dirty pages are a separate metric, not in the total.
						ch <- prometheus.MustNewConstMetric(
							infoSchemaBufferPoolPagesDirtyDesc, prometheus.GaugeValue, value,
						)
					default:
						ch <- prometheus.MustNewConstMetric(
							infoSchemaBufferPoolPagesDesc, prometheus.GaugeValue, value, match[2],
						)
					}
				}
				continue
			}
		}
		metricName := "innodb_metrics_" + subsystem + "_" + name
		metricDesc := func(suffix string) *prometheus.Desc {
			return prometheus.NewDesc(
				prometheus.BuildFQName(namespace, informationSchema, metricName+suffix),
				comment, nil, nil,
			)
		}

		if _, ok := innodbMetricGaugeOverrides[subsystem+"/"+name]; ok {
			ch <- prometheus.MustNewConstMetric(metricDesc(""), prometheus.GaugeValue, value)
			// Preserve the historical counter name for users that already query
			// it while also exposing the correctly typed gauge above.
			if (metricType == "counter" || metricType == "status_counter") && value >= 0 {
				ch <- prometheus.MustNewConstMetric(metricDesc("_total"), prometheus.CounterValue, value)
			}
			continue
		}

		// MySQL returns counters as counter/status_counter and set aggregates as
		// set_member/set_owner. A set_member needs the normal counter suffix,
		// while set_owner names already carry their aggregate suffix.
		if metricType == "set_member" && value >= 0 {
			// Preserve the historical unsuffixed gauge and add the corrected
			// counter so existing and current dashboards both keep working.
			if strings.HasSuffix(name, "_total") {
				// Avoid exporting the same fqName as both a gauge and counter.
				ch <- prometheus.MustNewConstMetric(metricDesc(""), prometheus.CounterValue, value)
				continue
			}
			ch <- prometheus.MustNewConstMetric(metricDesc(""), prometheus.GaugeValue, value)
			ch <- prometheus.MustNewConstMetric(metricDesc("_total"), prometheus.CounterValue, value)
			continue
		}
		if metricType == "set_owner" && value >= 0 {
			ch <- prometheus.MustNewConstMetric(metricDesc(""), prometheus.CounterValue, value)
			continue
		}

		// MySQL returns counters named two different ways. "counter" and "status_counter".
		// value >= 0 is necessary due to upstream bugs: http://bugs.mysql.com/bug.php?id=75966
		if (metricType == "counter" || metricType == "status_counter") && value >= 0 {
			ch <- prometheus.MustNewConstMetric(
				metricDesc("_total"),
				prometheus.CounterValue,
				value,
			)
		} else {
			ch <- prometheus.MustNewConstMetric(
				metricDesc(""),
				prometheus.GaugeValue,
				value,
			)
		}
	}
	return nil
}

// check interface
var _ Scraper = ScrapeInnodbMetrics{}
