// Copyright 2026 Percona LLC
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
	"regexp"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var fqNameRE = regexp.MustCompile(`fqName: "([^"]+)"`)

// metricsByName drains a metric channel into a map keyed by fqName so that
// assertions do not depend on emission order, and reports a metric emitted
// twice under one name - the failure mode that makes Gather() drop a family.
func metricsByName(t *testing.T, ch <-chan prometheus.Metric) map[string]MetricResult {
	t.Helper()

	collected := make(map[string]MetricResult)
	for metric := range ch {
		match := fqNameRE.FindStringSubmatch(metric.Desc().String())
		if match == nil {
			t.Fatalf("cannot parse fqName from %s", metric.Desc())
		}
		if _, seen := collected[match[1]]; seen {
			t.Errorf("metric %s was collected more than once", match[1])
		}
		collected[match[1]] = readMetric(metric)
	}
	return collected
}

// collectRedoStatus drains collect() through an unbuffered channel so that the
// tests cannot deadlock when the number of emitted metrics changes.
func collectRedoStatus(t *testing.T, status *innodbRedoStatus) map[string]MetricResult {
	t.Helper()

	ch := make(chan prometheus.Metric)
	go func() {
		defer close(ch)
		status.collect(ch)
	}()
	return metricsByName(t, ch)
}

func assertMetric(
	t *testing.T,
	collected map[string]MetricResult,
	name string,
	value float64,
	metricType dto.MetricType,
) {
	t.Helper()

	metric, ok := collected[name]
	if !ok {
		t.Errorf("metric %s was not collected", name)
		return
	}
	if metric.value != value {
		t.Errorf("metric %s value = %v, want %v", name, metric.value, value)
	}
	if metric.metricType != metricType {
		t.Errorf("metric %s type = %v, want %v", name, metric.metricType, metricType)
	}
}

func assertNoMetric(t *testing.T, collected map[string]MetricResult, names ...string) {
	t.Helper()

	for _, name := range names {
		if _, ok := collected[name]; ok {
			t.Errorf("metric %s must not be collected", name)
		}
	}
}

// Oracle MySQL 8.0.30 and newer, including 9.7: only the Innodb_redo_log_*
// variables exist, so every legacy name has to come from a compatibility alias.
func TestInnodbRedoStatusOracleMySQL(t *testing.T) {
	status := innodbRedoStatus{}
	status.observe("innodb_redo_log_current_lsn", 1500)
	status.observe("innodb_redo_log_checkpoint_lsn", 1000)
	status.observe("innodb_redo_log_flushed_to_disk_lsn", 1400)
	status.observe("innodb_redo_log_capacity_resized", 2000)
	status.observe("innodb_os_log_written", 4096)

	collected := collectRedoStatus(t, &status)

	assertMetric(t, collected, "mysql_innodb_redo_log_current_lsn", 1500, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_lsn", 1000, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_flushed_lsn", 1400, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_bytes", 500, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_ratio", 0.25, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_capacity_bytes", 2000, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_written_bytes_total", 4096, dto.MetricType_COUNTER)

	assertMetric(t, collected, "mysql_global_status_innodb_lsn_current", 1500, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_global_status_innodb_lsn_last_checkpoint", 1000, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_global_status_innodb_lsn_flushed", 1400, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_global_status_innodb_checkpoint_age", 500, dto.MetricType_GAUGE)

	// The redo log capacity is not the Percona sync flush threshold, so it must
	// not be published under the name of that threshold.
	assertNoMetric(t, collected, "mysql_global_status_innodb_checkpoint_max_age")
}

// Percona Server 8.0.30 and newer expose both name sets at once. The native
// values must win and no alias may be emitted, in either observation order.
func TestInnodbRedoStatusPerconaServerBothNameSets(t *testing.T) {
	observations := []struct {
		name  string
		order []struct {
			key   string
			value float64
		}
	}{
		{
			name: "legacy names first",
			order: []struct {
				key   string
				value float64
			}{
				{"innodb_lsn_current", 1500},
				{"innodb_lsn_flushed", 1400},
				{"innodb_lsn_last_checkpoint", 1000},
				{"innodb_checkpoint_age", 500},
				{"innodb_checkpoint_max_age", 1600},
				{"innodb_redo_log_current_lsn", 9501},
				{"innodb_redo_log_checkpoint_lsn", 9001},
				{"innodb_redo_log_flushed_to_disk_lsn", 9401},
				{"innodb_redo_log_capacity_resized", 2000},
			},
		},
		{
			name: "oracle names first",
			order: []struct {
				key   string
				value float64
			}{
				{"innodb_redo_log_current_lsn", 9501},
				{"innodb_redo_log_checkpoint_lsn", 9001},
				{"innodb_redo_log_flushed_to_disk_lsn", 9401},
				{"innodb_redo_log_capacity_resized", 2000},
				{"innodb_lsn_current", 1500},
				{"innodb_lsn_flushed", 1400},
				{"innodb_lsn_last_checkpoint", 1000},
				{"innodb_checkpoint_age", 500},
				{"innodb_checkpoint_max_age", 1600},
			},
		},
	}

	for _, observation := range observations {
		t.Run(observation.name, func(t *testing.T) {
			status := innodbRedoStatus{}
			for _, row := range observation.order {
				status.observe(row.key, row.value)
			}

			collected := collectRedoStatus(t, &status)

			assertMetric(t, collected, "mysql_innodb_redo_log_current_lsn", 1500, dto.MetricType_GAUGE)
			assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_lsn", 1000, dto.MetricType_GAUGE)
			assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_bytes", 500, dto.MetricType_GAUGE)
			// The canonical series carries the native value, not the Oracle one.
			assertMetric(t, collected, "mysql_innodb_redo_log_flushed_lsn", 1400, dto.MetricType_GAUGE)
			assertMetric(t, collected, "mysql_innodb_redo_log_capacity_bytes", 2000, dto.MetricType_GAUGE)
			assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_ratio", 0.25, dto.MetricType_GAUGE)

			// The server publishes all of these itself through the generic
			// global status path, so an alias would duplicate the series.
			assertNoMetric(t, collected,
				"mysql_global_status_innodb_lsn_current",
				"mysql_global_status_innodb_lsn_last_checkpoint",
				"mysql_global_status_innodb_lsn_flushed",
				"mysql_global_status_innodb_checkpoint_age",
				"mysql_global_status_innodb_checkpoint_max_age",
			)
		})
	}
}

// MySQL 5.7, Percona Server 5.7 and MariaDB: legacy names only and no
// Innodb_redo_log_capacity_resized, so capacity and the ratio cannot be
// derived and no alias is needed.
func TestInnodbRedoStatusLegacyNamesWithoutCapacity(t *testing.T) {
	status := innodbRedoStatus{}
	status.observe("innodb_lsn_current", 1500)
	status.observe("innodb_lsn_last_checkpoint", 1000)
	status.observe("innodb_lsn_flushed", 1400)
	status.observe("innodb_checkpoint_age", 500)
	status.observe("innodb_checkpoint_max_age", 1600)
	status.observe("innodb_os_log_written", 4096)

	collected := collectRedoStatus(t, &status)

	assertMetric(t, collected, "mysql_innodb_redo_log_current_lsn", 1500, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_lsn", 1000, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_bytes", 500, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_flushed_lsn", 1400, dto.MetricType_GAUGE)
	assertMetric(t, collected, "mysql_innodb_redo_log_written_bytes_total", 4096, dto.MetricType_COUNTER)

	assertNoMetric(t, collected,
		"mysql_innodb_redo_log_capacity_bytes",
		"mysql_innodb_redo_log_checkpoint_age_ratio",
		"mysql_global_status_innodb_lsn_current",
		"mysql_global_status_innodb_lsn_last_checkpoint",
		"mysql_global_status_innodb_lsn_flushed",
		"mysql_global_status_innodb_checkpoint_age",
	)
}

func TestInnodbRedoStatusGuards(t *testing.T) {
	t.Run("inverted LSNs yield no checkpoint age", func(t *testing.T) {
		status := innodbRedoStatus{}
		status.observe("innodb_redo_log_current_lsn", 1000)
		status.observe("innodb_redo_log_checkpoint_lsn", 1500)
		status.observe("innodb_redo_log_capacity_resized", 2000)

		collected := collectRedoStatus(t, &status)

		assertMetric(t, collected, "mysql_innodb_redo_log_current_lsn", 1000, dto.MetricType_GAUGE)
		assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_lsn", 1500, dto.MetricType_GAUGE)
		assertNoMetric(t, collected,
			"mysql_innodb_redo_log_checkpoint_age_bytes",
			"mysql_innodb_redo_log_checkpoint_age_ratio",
			"mysql_global_status_innodb_checkpoint_age",
		)
	})

	t.Run("zero capacity yields no ratio", func(t *testing.T) {
		// Reachable while the redo log is being resized, which is why the
		// server has an Innodb_redo_log_resize_status variable at all.
		status := innodbRedoStatus{}
		status.observe("innodb_redo_log_current_lsn", 1500)
		status.observe("innodb_redo_log_checkpoint_lsn", 1000)
		status.observe("innodb_redo_log_capacity_resized", 0)

		collected := collectRedoStatus(t, &status)

		assertMetric(t, collected, "mysql_innodb_redo_log_capacity_bytes", 0, dto.MetricType_GAUGE)
		assertMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_bytes", 500, dto.MetricType_GAUGE)
		assertNoMetric(t, collected, "mysql_innodb_redo_log_checkpoint_age_ratio")
	})
}
