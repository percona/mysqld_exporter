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

// Scrape `SHOW SLAVE STATUS`.

package collector

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"

	"github.com/blang/semver/v4"
	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Subsystem.
	slaveStatus = "slave_status"
)

// erParseError is the MySQL/MariaDB error number for a syntax error (ER_PARSE_ERROR).
const erParseError = 1064

var slaveStatusQueries = [3]string{"SHOW ALL SLAVES STATUS", "SHOW SLAVE STATUS", "SHOW REPLICA STATUS"}
var slaveStatusQuerySuffixes = [3]string{"", " NONBLOCKING", " NOLOCK"}

// MySQL 8.0.22 introduced SHOW REPLICA STATUS; 8.4 removed SHOW SLAVE STATUS.
var replicaStatusMinVersion = semver.MustParse("8.0.22")

// slaveStatusQuery returns the statement the server is known to support, based on the
// flavor and version detected for the instance. It returns "" when the flavor is unknown.
func slaveStatusQuery(instance *instance) string {
	switch {
	case instance.flavor == FlavorMariaDB:
		// Only the ALL form returns every named connection of a multi-source replica.
		return "SHOW ALL SLAVES STATUS"
	case instance.flavor == FlavorMySQL && instance.version.GTE(replicaStatusMinVersion):
		return "SHOW REPLICA STATUS"
	case instance.flavor == FlavorMySQL:
		return "SHOW SLAVE STATUS"
	default:
		return ""
	}
}

func isParseError(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == erParseError
}

// querySlaveStatus runs the statement matching the detected flavor and version, and only
// probes the other syntaxes (MariaDB, MySQL, lock-free variants) when that statement is
// rejected as a syntax error or the flavor is unknown. This avoids sending statements the
// server is known not to support on every scrape.
func querySlaveStatus(ctx context.Context, instance *instance) (*sql.Rows, error) {
	db := instance.getDB()
	preferred := slaveStatusQuery(instance)
	if preferred != "" {
		rows, err := db.QueryContext(ctx, preferred)
		if err == nil || !isParseError(err) {
			return rows, err
		}
	}

	var err error
	for _, query := range slaveStatusQueries {
		for _, suffix := range slaveStatusQuerySuffixes {
			statement := query + suffix
			if statement == preferred {
				continue
			}
			var rows *sql.Rows
			if rows, err = db.QueryContext(ctx, statement); err == nil {
				return rows, nil
			}
		}
	}
	return nil, err
}

func columnIndex(slaveCols []string, colName string) int {
	for idx := range slaveCols {
		if slaveCols[idx] == colName {
			return idx
		}
	}
	return -1
}

func columnValue(scanArgs []interface{}, slaveCols []string, colName string) string {
	var columnIndex = columnIndex(slaveCols, colName)
	if columnIndex == -1 {
		return ""
	}
	return string(*scanArgs[columnIndex].(*sql.RawBytes))
}

// ScrapeSlaveStatus collects from `SHOW SLAVE STATUS`.
type ScrapeSlaveStatus struct{}

// Name of the Scraper. Should be unique.
func (ScrapeSlaveStatus) Name() string {
	return slaveStatus
}

// Help describes the role of the Scraper.
func (ScrapeSlaveStatus) Help() string {
	return "Collect from SHOW SLAVE STATUS"
}

// Version of MySQL from which scraper is available.
func (ScrapeSlaveStatus) Version() float64 {
	return 5.1
}

// Scrape collects data from database connection and sends it over channel as prometheus metric.
func (ScrapeSlaveStatus) Scrape(ctx context.Context, instance *instance, ch chan<- prometheus.Metric, logger *slog.Logger) error {
	slaveStatusRows, err := querySlaveStatus(ctx, instance)
	if err != nil {
		return err
	}
	defer slaveStatusRows.Close()

	slaveCols, err := slaveStatusRows.Columns()
	if err != nil {
		return err
	}

	for slaveStatusRows.Next() {
		// As the number of columns varies with mysqld versions,
		// and sql.Scan requires []interface{}, we need to create a
		// slice of pointers to the elements of slaveData.
		scanArgs := make([]interface{}, len(slaveCols))
		for i := range scanArgs {
			scanArgs[i] = &sql.RawBytes{}
		}

		if err := slaveStatusRows.Scan(scanArgs...); err != nil {
			return err
		}

		masterUUID := columnValue(scanArgs, slaveCols, "Master_UUID")
		if masterUUID == "" {
			masterUUID = columnValue(scanArgs, slaveCols, "Source_UUID")
		}
		masterHost := columnValue(scanArgs, slaveCols, "Master_Host")
		if masterHost == "" {
			masterHost = columnValue(scanArgs, slaveCols, "Source_Host")
		}
		channelName := columnValue(scanArgs, slaveCols, "Channel_Name")       // MySQL & Percona
		connectionName := columnValue(scanArgs, slaveCols, "Connection_name") // MariaDB

		for i, col := range slaveCols {
			if value, ok := parseStatus(*scanArgs[i].(*sql.RawBytes)); ok { // Silently skip unparsable values.
				ch <- prometheus.MustNewConstMetric(
					prometheus.NewDesc(
						prometheus.BuildFQName(namespace, slaveStatus, strings.ToLower(col)),
						"Generic metric from SHOW SLAVE STATUS.",
						[]string{"master_host", "master_uuid", "channel_name", "connection_name"},
						nil,
					),
					prometheus.UntypedValue,
					value,
					masterHost, masterUUID, channelName, connectionName,
				)
			}
		}
	}
	return nil
}

// check interface
var _ Scraper = ScrapeSlaveStatus{}
