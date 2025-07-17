package collector

import (
	"context"
	"database/sql"

	"log/slog"
	"github.com/prometheus/client_golang/prometheus"
)

type ScrapePerfDataLocks struct{}

var (
	perfSchemaDataLocksDesc = prometheus.NewDesc(
		"mysql_performance_schema_data_locks",
		"Current row/table locks from performance_schema.data_locks.",
		[]string{"engine", "object_schema", "object_name", "lock_type", "lock_mode", "lock_status"}, nil,
	)
	perfSchemaDataLockWaitsDesc = prometheus.NewDesc(
		"mysql_performance_schema_data_lock_waits",
		"Current lock waits from performance_schema.data_lock_waits.",
		[]string{"requesting_engine_lock_id", "blocking_engine_lock_id"}, nil,
	)
)

func (ScrapePerfDataLocks) Name() string {
	return "perf_schema.data_locks"
}

func (ScrapePerfDataLocks) Help() string {
	return "Collects metrics from performance_schema.data_locks and data_lock_waits."
}

func (ScrapePerfDataLocks) Version() float64 {
	return 1.0
}

func (ScrapePerfDataLocks) Scrape(ctx context.Context, inst *collector.instance, ch chan<- prometheus.Metric, logger *slog.Logger) error {
	db := inst.db
	// data_locks
	locksRows, err := db.QueryContext(ctx, `SELECT ENGINE, OBJECT_SCHEMA, OBJECT_NAME, LOCK_TYPE, LOCK_MODE, LOCK_STATUS FROM performance_schema.data_locks`)
	if err != nil {
		logger.Error("Failed to query performance_schema.data_locks", "err", err)
		return err
	}
	defer locksRows.Close()
	for locksRows.Next() {
		var engine, objectSchema, objectName, lockType, lockMode, lockStatus string
		if err := locksRows.Scan(&engine, &objectSchema, &objectName, &lockType, &lockMode, &lockStatus); err != nil {
			logger.Error("Failed to scan row from data_locks", "err", err)
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			perfSchemaDataLocksDesc,
			prometheus.GaugeValue,
			1,
			engine, objectSchema, objectName, lockType, lockMode, lockStatus,
		)
	}
	// data_lock_waits
	waitsRows, err := db.QueryContext(ctx, `SELECT REQUESTING_ENGINE_LOCK_ID, BLOCKING_ENGINE_LOCK_ID FROM performance_schema.data_lock_waits`)
	if err != nil {
		logger.Error("Failed to query performance_schema.data_lock_waits", "err", err)
		return err
	}
	defer waitsRows.Close()
	for waitsRows.Next() {
		var requesting, blocking string
		if err := waitsRows.Scan(&requesting, &blocking); err != nil {
			logger.Error("Failed to scan row from data_lock_waits", "err", err)
			continue
		}
		ch <- prometheus.MustNewConstMetric(
			perfSchemaDataLockWaitsDesc,
			prometheus.GaugeValue,
			1,
			requesting, blocking,
		)
	}
	return nil
} 