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

// stableInnodbMetrics gives dashboards one short name per metric that does not
// encode the row's SUBSYSTEM or the "_total" suffix this collector derives from
// its TYPE. The generic metrics are kept and these aliases are emitted in
// addition.
//
// The aliases are a forward-looking guarantee, not a fix for drift that has
// already happened: measured on MySQL 8.0.46, 9.7.0, Percona Server 8.4.6,
// Percona Server 5.7.35 and MariaDB 10.11, all thirteen rows below report the
// same SUBSYSTEM and the same TYPE, so for the eleven counter and status_counter
// rows the alias renames a generic name that is already identical on every
// supported server. That a row can move is not hypothetical - it happened to
// the log_lsn_* rows between 5.7 and 8.0, which is what
// innodbMetricGaugeOverrides below deals with - but it has not happened to
// these, so do not describe them as a compatibility shim.
//
// The two "buffer" entries are the only ones that change what this collector
// exports today. They are set_member and set_owner rows, which the generic
// branch exported solely as an unsuffixed gauge, so rate() over them was not
// valid; membership here also emits the correctly typed "_total" counter.
//
// Keyed by "<subsystem>/<name>" so that an alias cannot be emitted twice should
// a future release report one of these names under a second subsystem: two
// identical fqNames make Gather() drop the whole metric family.
//
// Every entry maps to a monotonically increasing counter, so the aliases are
// always exported as CounterValue regardless of the TYPE MySQL reports for the
// source row. Only add names here that are genuinely cumulative counters.
//
// Entries also make the generic collector emit a "<name>_total" counter next to
// the historical gauge, so do not add a name whose subsystem already contains a
// row literally called "<name>_total": the two would collide on one fqName.
var stableInnodbMetrics = map[string]stableInnodbMetric{
	"buffer/buffer_flush_neighbor": {
		name: "buffer_flush_neighbor_batches_total",
		help: "Total number of neighbor page flush batches.",
	},
	"buffer/buffer_flush_neighbor_total_pages": {
		name: "buffer_flush_neighbor_pages_total",
		help: "Total number of pages flushed by neighbor page flushing.",
	},
	"purge/purge_invoked": {
		name: "purge_invocations_total",
		help: "Total number of times purge was invoked.",
	},
	"purge/purge_upd_exist_or_extern_records": {
		name: "purge_updated_records_total",
		help: "Total number of updated records processed by purge.",
	},
	"purge/purge_del_mark_records": {
		name: "purge_delete_marked_records_total",
		help: "Total number of delete-marked records processed by purge.",
	},
	"transaction/trx_rw_commits": {
		name: "transactions_read_write_committed_total",
		help: "Total number of committed read-write transactions.",
	},
	"adaptive_hash_index/adaptive_hash_rows_added": {
		name: "adaptive_hash_rows_added_total",
		help: "Total number of rows added to the adaptive hash index.",
	},
	"adaptive_hash_index/adaptive_hash_rows_removed": {
		name: "adaptive_hash_rows_removed_total",
		help: "Total number of rows removed from the adaptive hash index.",
	},
	"adaptive_hash_index/adaptive_hash_rows_updated": {
		name: "adaptive_hash_rows_updated_total",
		help: "Total number of rows updated in the adaptive hash index.",
	},
	"adaptive_hash_index/adaptive_hash_pages_added": {
		name: "adaptive_hash_pages_added_total",
		help: "Total number of pages added to the adaptive hash index.",
	},
	"adaptive_hash_index/adaptive_hash_pages_removed": {
		name: "adaptive_hash_pages_removed_total",
		help: "Total number of pages removed from the adaptive hash index.",
	},
	"adaptive_hash_index/adaptive_hash_searches": {
		name: "adaptive_hash_searches_total",
		help: "Total number of adaptive hash index searches.",
	},
	"adaptive_hash_index/adaptive_hash_searches_btree": {
		name: "adaptive_hash_btree_searches_total",
		help: "Total number of B-tree searches that bypassed the adaptive hash index.",
	},
}

// These values are positions or sizes rather than monotonically increasing
// event counters, but the TYPE reported for them is not stable across versions:
// 5.7 reports them under "recovery" with log_lsn_checkpoint_age as a counter,
// while 8.0, 8.4, 9.7 and Percona Server 8.0 report all six under "log" as
// values. The override is therefore a guard, not a description of current
// server behaviour: on 8.0 and newer it emits exactly what the generic branch
// below would. It keeps the unsuffixed gauge that dashboards need for
// max_over_time and direct arithmetic even if a release flips one of these rows
// to a counter. Dashboards query both the "log" and the "recovery" spelling, so
// both are listed.
//
// log_max_modified_age_sync is the synchronous flush threshold and the primary
// denominator of the PMM redo log advisor. Were a release to report that row as
// a counter, it would move to the "_total" spelling, the advisor's threshold
// term would resolve to nothing, and the check would fall through to the lower
// _async threshold and start firing earlier with no sign the denominator had
// changed.
var innodbMetricGaugeOverrides = map[string]struct{}{
	"log/log_lsn_checkpoint_age":          {},
	"log/log_lsn_current":                 {},
	"log/log_lsn_last_checkpoint":         {},
	"log/log_lsn_last_flush":              {},
	"log/log_max_modified_age_async":      {},
	"log/log_max_modified_age_sync":       {},
	"recovery/log_lsn_checkpoint_age":     {},
	"recovery/log_lsn_current":            {},
	"recovery/log_lsn_last_checkpoint":    {},
	"recovery/log_lsn_last_flush":         {},
	"recovery/log_max_modified_age_async": {},
	"recovery/log_max_modified_age_sync":  {},
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
		metricKey := subsystem + "/" + name
		if stable, ok := stableInnodbMetrics[metricKey]; ok && value >= 0 {
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

		if _, ok := innodbMetricGaugeOverrides[metricKey]; ok {
			isCounter := metricType == "counter" || metricType == "status_counter"
			// Some MySQL versions report these overridden metrics as counters
			// and can emit the -1 sentinel due to an upstream bug
			// (http://bugs.mysql.com/bug.php?id=75966). A negative value is not
			// a valid sample for either the gauge or the counter, so skip it.
			if isCounter && value < 0 {
				continue
			}
			ch <- prometheus.MustNewConstMetric(metricDesc(""), prometheus.GaugeValue, value)
			// Preserve the historical counter name for users that already query
			// it while also exposing the correctly typed gauge above.
			if isCounter {
				ch <- prometheus.MustNewConstMetric(metricDesc("_total"), prometheus.CounterValue, value)
			}
			continue
		}

		// Only the known cumulative rows listed in stableInnodbMetrics can
		// safely be exposed as counters. Other set rows hold derived values
		// such as averages or per-call figures that may decrease.
		isSetRow := metricType == "set_member" || metricType == "set_owner"
		if _, ok := stableInnodbMetrics[metricKey]; ok && isSetRow && value >= 0 {
			// Both row types were historically exported as an unsuffixed
			// gauge. Preserve that name and add the correctly typed counter so
			// existing and current dashboards both keep working.
			ch <- prometheus.MustNewConstMetric(metricDesc(""), prometheus.GaugeValue, value)
			ch <- prometheus.MustNewConstMetric(metricDesc("_total"), prometheus.CounterValue, value)
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
