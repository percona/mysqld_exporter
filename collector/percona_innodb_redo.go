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

import "github.com/prometheus/client_golang/prometheus"

var (
	innodbRedoCurrentLSNDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "innodb_redo_log", "current_lsn"),
		"Current InnoDB redo log sequence number.", nil, nil,
	)
	innodbRedoCheckpointLSNDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "innodb_redo_log", "checkpoint_lsn"),
		"InnoDB redo log checkpoint log sequence number.", nil, nil,
	)
	innodbRedoCheckpointAgeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "innodb_redo_log", "checkpoint_age_bytes"),
		"Bytes of InnoDB redo generated since the last checkpoint.", nil, nil,
	)
	innodbRedoCapacityDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "innodb_redo_log", "capacity_bytes"),
		"Total InnoDB redo log capacity in bytes.", nil, nil,
	)
	innodbRedoWrittenDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "innodb_redo_log", "written_bytes_total"),
		"Total bytes written to the InnoDB redo log files.", nil, nil,
	)
	innodbRedoUsageDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "innodb_redo_log", "checkpoint_age_ratio"),
		"Ratio of InnoDB checkpoint age to total redo log capacity.", nil, nil,
	)

	// Compatibility descriptors preserve the status names that Percona Server,
	// MySQL 5.7 and MariaDB expose but Oracle MySQL never had: Oracle covers the
	// same ground with the Innodb_redo_log_* variables introduced by the 8.0.30
	// redo log rework. Dashboards querying the historical names therefore see
	// nothing on Oracle MySQL 8.0.30 and newer, and these aliases keep them
	// working while they migrate to the stable mysql_innodb_redo_log_* metrics
	// above.
	//
	// There is deliberately no alias for Innodb_checkpoint_max_age: on Percona
	// Server it reports the sync flush threshold, whereas the only comparable
	// value Oracle exposes is the full redo log capacity, so a single series
	// name would mean different things per vendor. Dashboards use
	// mysql_innodb_redo_log_capacity_bytes as the limit series instead.
	innodbLSNCurrentCompatDesc = newDesc(
		globalStatus, "innodb_lsn_current", "Current InnoDB redo log sequence number.",
	)
	innodbLSNLastCheckpointCompatDesc = newDesc(
		globalStatus, "innodb_lsn_last_checkpoint", "InnoDB redo log checkpoint log sequence number.",
	)
	// Paired with innodb_lsn_current by the log buffer usage panels, which
	// subtract the two, so the alias is only useful if both are present.
	innodbLSNFlushedCompatDesc = newDesc(
		globalStatus, "innodb_lsn_flushed", "InnoDB redo log sequence number flushed to disk.",
	)
	innodbCheckpointAgeCompatDesc = newDesc(
		globalStatus, "innodb_checkpoint_age", "Bytes of InnoDB redo generated since the last checkpoint.",
	)
)

type innodbRedoStatus struct {
	currentLSN             float64
	checkpointLSN          float64
	flushedLSN             float64
	checkpointAge          float64
	capacity               float64
	written                float64
	hasCurrentLSN          bool
	hasCheckpointLSN       bool
	hasFlushedLSN          bool
	hasCheckpointAge       bool
	hasCapacity            bool
	hasWritten             bool
	hasLegacyCurrent       bool
	hasLegacyCheckpoint    bool
	hasLegacyFlushed       bool
	hasLegacyCheckpointAge bool
}

func (s *innodbRedoStatus) observe(key string, value float64) {
	switch key {
	case "innodb_lsn_current":
		s.currentLSN = value
		s.hasCurrentLSN = true
		s.hasLegacyCurrent = true
	case "innodb_redo_log_current_lsn":
		if !s.hasLegacyCurrent {
			s.currentLSN = value
			s.hasCurrentLSN = true
		}
	case "innodb_lsn_last_checkpoint":
		s.checkpointLSN = value
		s.hasCheckpointLSN = true
		s.hasLegacyCheckpoint = true
	case "innodb_redo_log_checkpoint_lsn":
		if !s.hasLegacyCheckpoint {
			s.checkpointLSN = value
			s.hasCheckpointLSN = true
		}
	case "innodb_lsn_flushed":
		s.flushedLSN = value
		s.hasFlushedLSN = true
		s.hasLegacyFlushed = true
	case "innodb_redo_log_flushed_to_disk_lsn":
		if !s.hasLegacyFlushed {
			s.flushedLSN = value
			s.hasFlushedLSN = true
		}
	case "innodb_checkpoint_age":
		s.checkpointAge = value
		s.hasCheckpointAge = true
		s.hasLegacyCheckpointAge = true
	case "innodb_redo_log_capacity_resized":
		s.capacity = value
		s.hasCapacity = true
	case "innodb_os_log_written":
		s.written = value
		s.hasWritten = true
	}
}

func (s *innodbRedoStatus) collect(ch chan<- prometheus.Metric) {
	if s.hasCurrentLSN {
		ch <- prometheus.MustNewConstMetric(innodbRedoCurrentLSNDesc, prometheus.GaugeValue, s.currentLSN)
		if !s.hasLegacyCurrent {
			ch <- prometheus.MustNewConstMetric(innodbLSNCurrentCompatDesc, prometheus.GaugeValue, s.currentLSN)
		}
	}
	if s.hasCheckpointLSN {
		ch <- prometheus.MustNewConstMetric(innodbRedoCheckpointLSNDesc, prometheus.GaugeValue, s.checkpointLSN)
		if !s.hasLegacyCheckpoint {
			ch <- prometheus.MustNewConstMetric(innodbLSNLastCheckpointCompatDesc, prometheus.GaugeValue, s.checkpointLSN)
		}
	}

	if s.hasFlushedLSN && !s.hasLegacyFlushed {
		ch <- prometheus.MustNewConstMetric(innodbLSNFlushedCompatDesc, prometheus.GaugeValue, s.flushedLSN)
	}

	if !s.hasCheckpointAge && s.hasCurrentLSN && s.hasCheckpointLSN && s.currentLSN >= s.checkpointLSN {
		s.checkpointAge = s.currentLSN - s.checkpointLSN
		s.hasCheckpointAge = true
	}
	if s.hasCheckpointAge {
		ch <- prometheus.MustNewConstMetric(innodbRedoCheckpointAgeDesc, prometheus.GaugeValue, s.checkpointAge)
		if !s.hasLegacyCheckpointAge {
			ch <- prometheus.MustNewConstMetric(innodbCheckpointAgeCompatDesc, prometheus.GaugeValue, s.checkpointAge)
		}
		if s.hasCapacity && s.capacity > 0 {
			ch <- prometheus.MustNewConstMetric(innodbRedoUsageDesc, prometheus.GaugeValue, s.checkpointAge/s.capacity)
		}
	}
	if s.hasCapacity {
		ch <- prometheus.MustNewConstMetric(innodbRedoCapacityDesc, prometheus.GaugeValue, s.capacity)
	}
	if s.hasWritten {
		ch <- prometheus.MustNewConstMetric(innodbRedoWrittenDesc, prometheus.CounterValue, s.written)
	}
}
