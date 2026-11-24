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
