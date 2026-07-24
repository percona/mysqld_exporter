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
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestInnodbRedoStatusMySQL97(t *testing.T) {
	status := innodbRedoStatus{}
	status.observe("innodb_redo_log_current_lsn", 1500)
	status.observe("innodb_redo_log_checkpoint_lsn", 1000)
	status.observe("innodb_redo_log_capacity_resized", 2000)
	status.observe("innodb_os_log_written", 4096)

	ch := make(chan prometheus.Metric, 10)
	status.collect(ch)
	close(ch)

	type expectedMetric struct {
		value      float64
		metricType dto.MetricType
	}
	expected := map[string]expectedMetric{
		"mysql_innodb_redo_log_current_lsn":              {1500, dto.MetricType_GAUGE},
		"mysql_global_status_innodb_lsn_current":         {1500, dto.MetricType_GAUGE},
		"mysql_innodb_redo_log_checkpoint_lsn":           {1000, dto.MetricType_GAUGE},
		"mysql_global_status_innodb_lsn_last_checkpoint": {1000, dto.MetricType_GAUGE},
		"mysql_innodb_redo_log_checkpoint_age_bytes":     {500, dto.MetricType_GAUGE},
		"mysql_global_status_innodb_checkpoint_age":      {500, dto.MetricType_GAUGE},
		"mysql_innodb_redo_log_checkpoint_age_ratio":     {0.25, dto.MetricType_GAUGE},
		"mysql_innodb_redo_log_capacity_bytes":           {2000, dto.MetricType_GAUGE},
		"mysql_global_status_innodb_checkpoint_max_age":  {2000, dto.MetricType_GAUGE},
		"mysql_innodb_redo_log_written_bytes_total":      {4096, dto.MetricType_COUNTER},
	}

	found := make(map[string]bool, len(expected))
	for metric := range ch {
		desc := metric.Desc().String()
		for name, want := range expected {
			if !strings.Contains(desc, `fqName: "`+name+`"`) {
				continue
			}
			if found[name] {
				t.Errorf("metric %s was collected more than once", name)
			}
			got := readMetric(metric)
			if got.value != want.value {
				t.Errorf("metric %s value = %v, want %v", name, got.value, want.value)
			}
			if got.metricType != want.metricType {
				t.Errorf("metric %s type = %v, want %v", name, got.metricType, want.metricType)
			}
			found[name] = true
		}
	}
	for name := range expected {
		if !found[name] {
			t.Errorf("redo metric %s was not collected", name)
		}
	}
}

func TestInnodbRedoStatusDoesNotDuplicatePerconaMetrics(t *testing.T) {
	status := innodbRedoStatus{}
	status.observe("innodb_lsn_current", 1500)
	status.observe("innodb_lsn_last_checkpoint", 1000)
	status.observe("innodb_checkpoint_age", 500)
	status.observe("innodb_checkpoint_max_age", 2000)

	ch := make(chan prometheus.Metric, 5)
	status.collect(ch)
	close(ch)

	for metric := range ch {
		desc := metric.Desc().String()
		if strings.Contains(desc, "mysql_global_status_innodb_") {
			t.Errorf("unexpected compatibility metric for Percona status variables: %s", desc)
		}
	}
}
