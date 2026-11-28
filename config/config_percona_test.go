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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
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

// writeTestCertificate writes a self-signed certificate and its key, and returns both paths.
func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mysqld-exporter-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))

	return certFile, keyFile
}

func TestPerconaTLSRules(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	garbageFile := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(garbageFile, []byte("not a certificate\n"), 0o600))

	const section = "client"
	ca := "ssl-ca=" + certFile
	cert := "ssl-cert=" + certFile
	key := "ssl-key=" + keyFile

	for _, tt := range []struct {
		name       string
		options    []string
		skipVerify bool
		wantTLS    string
		wantCA     bool
		wantCerts  int
		wantErr    string
	}{
		{name: "no TLS options"},
		{name: "skip-verify alone", skipVerify: true, wantTLS: "skip-verify"},
		{name: "skip-verify wins over ca, cert and key", options: []string{ca, cert, key}, skipVerify: true, wantTLS: "skip-verify"},
		{name: "skip-verify from my.cnf wins over ca, cert and key", options: []string{ca, cert, key, "ssl-skip-verfication=true"}, wantTLS: "skip-verify"}, //nolint:misspell
		{name: "skip-verify ignores unreadable files", options: []string{ca, "ssl-cert=" + garbageFile, "ssl-key=" + garbageFile}, skipVerify: true, wantTLS: "skip-verify"},
		{name: "ca, cert and key", options: []string{ca, cert, key}, wantTLS: section, wantCA: true, wantCerts: 1},
		{name: "ca alone", options: []string{ca}, wantTLS: section, wantCA: true},
		{name: "ca replaces the tls option", options: []string{ca, "tls=skip-verify"}, wantTLS: section, wantCA: true},
		{name: "ca with cert but no key", options: []string{ca, cert}, wantTLS: section, wantCA: true},
		{name: "ca with key but no cert", options: []string{ca, key}, wantTLS: section, wantCA: true},
		{name: "cert and key without ca are ignored", options: []string{cert, key}},
		{name: "cert and key without ca keep the tls option", options: []string{cert, key, "tls=true"}, wantTLS: "true"},
		{name: "unreadable cert and key without ca are ignored", options: []string{"ssl-cert=" + garbageFile, "ssl-key=" + garbageFile}},
		{name: "ca with unreadable cert and key", options: []string{ca, "ssl-cert=" + garbageFile, "ssl-key=" + garbageFile}, wantErr: "failed to parse pem-encoded SSL cert"},
		{name: "unreadable ca", options: []string{"ssl-ca=" + garbageFile}, wantErr: "failed to parse pem-encoded CA certificates"},
		{name: "tls-server-name follows the upstream rules", options: []string{cert, key, "tls-server-name=mysql.example"}, wantTLS: section, wantCerts: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Cleanup(func() { mysql.DeregisterTLSConfig(section) })

			cnf := filepath.Join(t.TempDir(), "my.cnf")
			content := "[client]\nuser=root\nhost=127.0.0.1\nport=3306\n" + strings.Join(tt.options, "\n") + "\n"
			require.NoError(t, os.WriteFile(cnf, []byte(content), 0o600))

			handler, err := NewAuthConfigHandler(prometheus.NewRegistry())
			require.NoError(t, err)
			require.NoError(t, handler.ReloadConfig(cnf, "localhost:3306", "", tt.skipVerify, promslog.NewNopLogger()))

			dsn, err := handler.GetConfig().Sections[section].FormDSN("", section)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			parsed, err := mysql.ParseDSN(dsn)
			require.NoError(t, err)
			assert.Equal(t, tt.wantTLS, parsed.TLSConfig)
			if tt.wantTLS == "" {
				assert.Nil(t, parsed.TLS)
				return
			}
			require.NotNil(t, parsed.TLS)
			assert.Len(t, parsed.TLS.Certificates, tt.wantCerts)
			assert.Equal(t, tt.wantTLS == "skip-verify", parsed.TLS.InsecureSkipVerify)
			assert.Equal(t, tt.wantCA, parsed.TLS.RootCAs != nil)
		})
	}
}

func TestValidatePercona(t *testing.T) {
	valid := func() Config {
		cfg := NewConfigWithDefaults()
		cfg.DataSourceName = "root@tcp(localhost:3306)/"
		return cfg
	}

	// Values upstream rejects for options the fork passes through unchecked.
	cfg := valid()
	cfg.ExporterLockWaitTimeoutSeconds = -1
	cfg.ExporterMaxOpenConns = 0
	cfg.ExporterMaxIdleConns = -1
	cfg.ExporterConnMaxLifetime = -time.Second
	cfg.Heartbeat = HeartbeatConfig{}
	cfg.InfoSchemaProcesslist.MinTime = -1
	cfg.InfoSchemaTables.Databases = ""
	cfg.PerfSchemaEventsStatements = PerfSchemaEventsStatementsConfig{}
	cfg.PerfSchemaFileInstances.Filter = ""
	require.Error(t, cfg.Validate())
	require.NoError(t, cfg.ValidatePercona())
	assert.Equal(t, 0, cfg.ExporterMaxOpenConns)

	// A data source name that cannot be used is reported by the scrape as mysql_up 0.
	cfg.DataSourceName = ""
	require.NoError(t, cfg.ValidatePercona())

	for name, change := range map[string]func(*Config){
		"negative query timeout": func(c *Config) { c.ExporterQueryTimeout = -time.Second },
		"unknown collector":      func(c *Config) { c.Collectors["unknown"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid()
			change(&cfg)
			require.Error(t, cfg.ValidatePercona())
		})
	}
}

func TestPerconaTLSConfigNameForReservedSections(t *testing.T) {
	certFile, _ := writeTestCertificate(t)

	for _, section := range []string{"true", "TRUE", "false", "1", "0", "skip-verify", "preferred", "client"} {
		t.Run(section, func(t *testing.T) {
			cfg := MySqlConfig{User: "root", SslCa: certFile}
			dsn, err := cfg.FormDSN("mysql.example:3306", section)
			require.NoError(t, err)
			t.Cleanup(func() { mysql.DeregisterTLSConfig(perconaTLSConfigName(section)) })

			parsed, err := mysql.ParseDSN(dsn)
			require.NoError(t, err)
			require.NotNil(t, parsed.TLS)
			assert.NotNil(t, parsed.TLS.RootCAs)
			assert.False(t, parsed.TLS.InsecureSkipVerify)
		})
	}

	// Other section names stay the registration name, as upstream has it.
	assert.Equal(t, "client.server1", perconaTLSConfigName("client.server1"))
}
