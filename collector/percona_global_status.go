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

// Scrape `SHOW GLOBAL STATUS`.

package collector

import (
	"context"
	"database/sql"
	"log/slog"
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Scrape query.
	pGlobalStatusQuery = `SHOW GLOBAL STATUS`
	// Subsystem.
	pGlobalStatus = "global_status"
)

// Regexp to match various groups of status vars.
var pGlobalStatusRE = regexp.MustCompile(`^(com|handler|connection_errors|innodb_buffer_pool_pages|innodb_rows|performance_schema)_(.*)$`)

// Metric descriptors.
var (
	pGlobalCommandsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, pGlobalStatus, "commands_total"),
		"Total number of executed MySQL commands.",
		[]string{"command"}, nil,
	)
	pGlobalHandlerDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, pGlobalStatus, "handlers_total"),
		"Total number of executed MySQL handlers.",
		[]string{"handler"}, nil,
	)
	pGlobalConnectionErrorsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, pGlobalStatus, "connection_errors_total"),
		"Total number of MySQL connection errors.",
		[]string{"error"}, nil,
	)
	pGlobalBufferPoolPagesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, pGlobalStatus, "buffer_pool_pages"),
		"Innodb buffer pool pages by state.",
		[]string{"state"}, nil,
	)
	pGlobalBufferPoolDirtyPagesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, pGlobalStatus, "buffer_pool_dirty_pages"),
		"Innodb buffer pool dirty pages.",
		[]string{"dirty"}, nil,
	)
	pGlobalBufferPoolPageChangesDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, pGlobalStatus, "buffer_pool_page_changes_total"),
		"Innodb buffer pool page state changes.",
		[]string{"operation"}, nil,
	)
	pGlobalInnoDBRowOpsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, pGlobalStatus, "innodb_row_ops_total"),
		"Total number of MySQL InnoDB row operations.",
		[]string{"operation"}, nil,
	)
	pGlobalPerformanceSchemaLostDesc = prometheus.NewDesc(
		prometheus.BuildFQName(Namespace, pGlobalStatus, "performance_schema_lost_total"),
		"Total number of MySQL instrumentations that could not be loaded or created due to memory constraints.",
		[]string{"instrumentation"}, nil,
	)
)

// ScrapeGlobalStatus collects from `SHOW GLOBAL STATUS`.
type PScrapeGlobalStatus struct{}

// Name of the Scraper. Should be unique.
func (PScrapeGlobalStatus) Name() string {
	return pGlobalStatus
}

// Help describes the role of the Scraper.
func (PScrapeGlobalStatus) Help() string {
	return "Collect from SHOW GLOBAL STATUS"
}

// Version of MySQL from which scraper is available.
func (PScrapeGlobalStatus) Version() float64 {
	return 5.1
}

// Scrape collects data from database connection and sends it over channel as prometheus metric.
func (PScrapeGlobalStatus) Scrape(ctx context.Context, instance *instance, ch chan<- prometheus.Metric, logger *slog.Logger) error {
	db := instance.getDB()
	globalStatusRows, err := db.QueryContext(ctx, pGlobalStatusQuery)
	if err != nil {
		return err
	}
	defer globalStatusRows.Close()

	var key string
	var val sql.RawBytes
	var textItems = map[string]string{
		"wsrep_local_state_uuid":   "",
		"wsrep_cluster_state_uuid": "",
		"wsrep_provider_version":   "",
		"wsrep_evs_repl_latency":   "",
	}

	for globalStatusRows.Next() {
		if err := globalStatusRows.Scan(&key, &val); err != nil {
			return err
		}
		if floatVal, ok := ParseStatus(val); ok { // Unparsable values are silently skipped.
			key = ValidPrometheusName(key)
			match := pGlobalStatusRE.FindStringSubmatch(key)
			if match == nil {
				ch <- prometheus.MustNewConstMetric(
					NewDesc(pGlobalStatus, key, "Generic metric from SHOW GLOBAL STATUS."),
					prometheus.UntypedValue,
					floatVal,
				)
				continue
			}
			switch match[1] {
			case "com":
				ch <- prometheus.MustNewConstMetric(
					pGlobalCommandsDesc, prometheus.CounterValue, floatVal, match[2],
				)
			case "handler":
				ch <- prometheus.MustNewConstMetric(
					pGlobalHandlerDesc, prometheus.CounterValue, floatVal, match[2],
				)
			case "connection_errors":
				ch <- prometheus.MustNewConstMetric(
					pGlobalConnectionErrorsDesc, prometheus.CounterValue, floatVal, match[2],
				)
			case "innodb_buffer_pool_pages":
				switch match[2] {
				case "data", "free", "misc", "old", "total":
					ch <- prometheus.MustNewConstMetric(
						pGlobalBufferPoolPagesDesc, prometheus.GaugeValue, floatVal, match[2],
					)
				case "dirty":
					ch <- prometheus.MustNewConstMetric(
						pGlobalBufferPoolDirtyPagesDesc, prometheus.GaugeValue, floatVal, match[2],
					)
				default:
					ch <- prometheus.MustNewConstMetric(
						pGlobalBufferPoolPageChangesDesc, prometheus.CounterValue, floatVal, match[2],
					)
				}
			case "innodb_rows":
				ch <- prometheus.MustNewConstMetric(
					pGlobalInnoDBRowOpsDesc, prometheus.CounterValue, floatVal, match[2],
				)
			case "performance_schema":
				ch <- prometheus.MustNewConstMetric(
					pGlobalPerformanceSchemaLostDesc, prometheus.CounterValue, floatVal, match[2],
				)
			}
		} else if _, ok := textItems[key]; ok {
			textItems[key] = string(val)
		}
	}

	// mysql_galera_variables_info metric.
	if textItems["wsrep_local_state_uuid"] != "" {
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc(prometheus.BuildFQName(Namespace, "galera", "status_info"), "PXC/Galera status information.",
				[]string{"wsrep_local_state_uuid", "wsrep_cluster_state_uuid", "wsrep_provider_version"}, nil),
			prometheus.GaugeValue, 1, textItems["wsrep_local_state_uuid"], textItems["wsrep_cluster_state_uuid"], textItems["wsrep_provider_version"],
		)
	}

	// mysql_galera_evs_repl_latency
	if textItems["wsrep_evs_repl_latency"] != "" {

		type evsValue struct {
			name  string
			value float64
			index int
			help  string
		}

		evsMap := []evsValue{
			{name: "min_seconds", value: 0, index: 0, help: "PXC/Galera group communication latency. Min value."},
			{name: "avg_seconds", value: 0, index: 1, help: "PXC/Galera group communication latency. Avg value."},
			{name: "max_seconds", value: 0, index: 2, help: "PXC/Galera group communication latency. Max value."},
			{name: "stdev", value: 0, index: 3, help: "PXC/Galera group communication latency. Standard Deviation."},
			{name: "sample_size", value: 0, index: 4, help: "PXC/Galera group communication latency. Sample Size."},
		}

		evsParsingSuccess := true
		values := strings.Split(textItems["wsrep_evs_repl_latency"], "/")

		if len(evsMap) == len(values) {
			for i, v := range evsMap {
				evsMap[i].value, err = strconv.ParseFloat(values[v.index], 64)
				if err != nil {
					evsParsingSuccess = false
				}
			}

			if evsParsingSuccess {
				for _, v := range evsMap {
					key := prometheus.BuildFQName(Namespace, "galera_evs_repl_latency", v.name)
					desc := prometheus.NewDesc(key, v.help, []string{}, nil)
					ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, v.value)
				}
			}
		}
	}

	return nil
}

// check interface
var _ Scraper = PScrapeGlobalStatus{}
