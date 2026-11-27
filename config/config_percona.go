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
	"errors"
	"fmt"
)

// perconaCollectorConfig adapts the upstream collector set for PMM: every collector is
// disabled unless requested, the collectors maintained by Percona are added, and the
// upstream collectors they replace are kept under a ".prometheus" suffix.
func perconaCollectorConfig(collectors map[string]bool) map[string]bool {
	for name := range collectors {
		collectors[name] = false
	}
	for _, name := range []string{
		"global_status.prometheus",
		"info_schema.processlist.prometheus",
		"info_schema.innodb_cmp.prometheus",
		"info_schema.innodb_cmpmem.prometheus",
		"plugins",
		"custom_query.hr",
		"custom_query.mr",
		"custom_query.lr",
		"standard.go",
		"standard.process",
	} {
		collectors[name] = false
	}
	return collectors
}

// ValidatePercona checks the options upstream has added. The options the fork already had
// accept any value, and a data source name that cannot be used is left to the scrape, which
// reports it as mysql_up 0.
func (c Config) ValidatePercona() error {
	if c.ExporterQueryTimeout < 0 {
		return errors.New("exporter query timeout must not be negative")
	}
	known := DefaultCollectorConfig()
	for name := range c.Collectors {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("unknown collector '%s'", name)
		}
	}
	return nil
}

// keepPerconaTLSRules applies the fork's TLS rules to a section: skip-verify wins over the
// certificate files, and ssl-cert and ssl-key count only as a pair next to ssl-ca, which
// replaces the tls option. A section that sets tls-min-version, tls-max-version or
// tls-server-name follows the upstream rules.
func (m *MySqlConfig) keepPerconaTLSRules() {
	if m.TlsMinVersion != "" || m.TlsMaxVersion != "" || m.TlsServerName != "" {
		return
	}
	if m.TlsInsecureSkipVerify || m.SslCa == "" {
		m.SslCa, m.SslCert, m.SslKey = "", "", ""
		return
	}
	m.Tls = ""
	if m.SslCert == "" || m.SslKey == "" {
		m.SslCert, m.SslKey = "", ""
	}
}
