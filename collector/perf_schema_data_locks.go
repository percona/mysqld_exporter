// Copyright 2024 The Percona Authors
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

// Scrape `performance_schema.data_locks` and `performance_schema.data_lock_waits`.

package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	perfDataLocksQuery = `
		SELECT ENGINE, OBJECT_SCHEMA, OBJECT_NAME, LOCK_TYPE, LOCK_MODE, LOCK_STATUS
		FROM performance_schema.data_locks`
	perfDataLockWaitsQuery = `
		SELECT REQUESTING_ENGINE_LOCK_ID, BLOCKING_ENGINE_LOCK_ID
		FROM performance_schema.data_lock_waits`
)

var (
	performanceSchemaDataLocksDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, performanceSchema, "data_locks"),
		"Current row/table locks from performance_schema.data_locks.",
		[]string{"engine", "object_schema", "object_name", "lock_type", "lock_mode", "lock_status"}, nil,
	)
	performanceSchemaDataLockWaitsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, performanceSchema, "data_lock_waits"),
		"Current lock waits from performance_schema.data_lock_waits.",
		[]string{"requesting_engine_lock_id", "blocking_engine_lock_id"}, nil,
	)
)

// ScrapePerfSchemaDataLocks collects from `performance_schema.data_locks` and `performance_schema.data_lock_waits`.
type ScrapePerfSchemaDataLocks struct{}

func (ScrapePerfSchemaDataLocks) Name() string {
	return "perf_schema.data_locks"
}

func (ScrapePerfSchemaDataLocks) Help() string {
	return "Collect metrics from performance_schema.data_locks and data_lock_waits"
}

func (ScrapePerfSchemaDataLocks) Version() float64 {
	return 8.0
}

func (ScrapePerfSchemaDataLocks) Scrape(ctx context.Context, instance *instance, ch chan<- prometheus.Metric, logger *slog.Logger) error {
	logger.Info("Starting ScrapePerfSchemaDataLocks")
	db := instance.getDB()
	logger.Info("after getDB ScrapePerfSchemaDataLocks")

	// data_locks
	locksRows, err := db.QueryContext(ctx, perfDataLocksQuery)
	if err != nil {
		logger.Error("Failed to query performance_schema.data_locks", "err", err)
		return err
	}
	defer locksRows.Close()
	rowCount := 0
	for locksRows.Next() {
		var engine, objectSchema, objectName, lockType, lockMode, lockStatus string
		if err := locksRows.Scan(&engine, &objectSchema, &objectName, &lockType, &lockMode, &lockStatus); err != nil {
			logger.Error("Failed to scan row from data_locks", "err", err)
			continue
		}
		logger.Debug("data_locks row", "engine", engine, "object_schema", objectSchema, "object_name", objectName, "lock_type", lockType, "lock_mode", lockMode, "lock_status", lockStatus)
		ch <- prometheus.MustNewConstMetric(
			performanceSchemaDataLocksDesc,
			prometheus.GaugeValue,
			1,
			engine, objectSchema, objectName, lockType, lockMode, lockStatus,
		)
		rowCount++
	}
	logger.Info("data_locks rows processed", "count", rowCount)
	if rowCount == 0 {
		logger.Info("No rows found in performance_schema.data_locks")
	}

	// data_lock_waits
	waitsRows, err := db.QueryContext(ctx, perfDataLockWaitsQuery)
	if err != nil {
		logger.Error("Failed to query performance_schema.data_lock_waits", "err", err)
		return err
	}
	defer waitsRows.Close()
	waitsCount := 0
	for waitsRows.Next() {
		var requesting, blocking string
		if err := waitsRows.Scan(&requesting, &blocking); err != nil {
			logger.Error("Failed to scan row from data_lock_waits", "err", err)
			continue
		}
		logger.Debug("data_lock_waits row", "requesting", requesting, "blocking", blocking)
		ch <- prometheus.MustNewConstMetric(
			performanceSchemaDataLockWaitsDesc,
			prometheus.GaugeValue,
			1,
			requesting, blocking,
		)
		waitsCount++
	}
	logger.Info("data_lock_waits rows processed", "count", waitsCount)
	if waitsCount == 0 {
		logger.Info("No rows found in performance_schema.data_lock_waits")
	}
	return nil
}

// check interface
var _ Scraper = ScrapePerfSchemaDataLocks{}
