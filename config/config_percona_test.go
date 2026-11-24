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

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerconaCollectorConfig(t *testing.T) {
	collectors := DefaultCollectorConfig()

	for name, enabled := range collectors {
		assert.False(t, enabled, "collector %s must be disabled by default", name)
	}

	for _, name := range []string{
		"global_status",
		"global_status.prometheus",
		"info_schema.processlist",
		"info_schema.processlist.prometheus",
		"info_schema.innodb_cmp",
		"info_schema.innodb_cmp.prometheus",
		"info_schema.innodb_cmpmem",
		"info_schema.innodb_cmpmem.prometheus",
		"plugins",
		"custom_query.hr",
		"custom_query.mr",
		"custom_query.lr",
		"standard.go",
		"standard.process",
	} {
		assert.Contains(t, collectors, name)
	}
}

func TestPerconaCollectorsPassValidation(t *testing.T) {
	cfg := NewConfigWithDefaults()
	cfg.DataSourceName = "root@tcp(localhost:3306)/"
	for name := range cfg.Collectors {
		cfg.Collectors[name] = true
	}

	require.NoError(t, cfg.Validate())
}

func TestPerconaConnectionPoolDefaults(t *testing.T) {
	cfg := NewConfigWithDefaults()

	assert.Equal(t, 3, cfg.ExporterMaxOpenConns)
	assert.Equal(t, 3, cfg.ExporterMaxIdleConns)
	assert.Equal(t, time.Minute, cfg.ExporterConnMaxLifetime)
}
