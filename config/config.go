// Copyright 2022 The Prometheus Authors
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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"

	"gopkg.in/ini.v1"
)

var (
	configReloadSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "mysqld_exporter",
		Name:      "config_last_reload_successful",
		Help:      "Mysqld exporter config loaded successfully.",
	})

	configReloadSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "mysqld_exporter",
		Name:      "config_last_reload_success_timestamp_seconds",
		Help:      "Timestamp of the last successful configuration reload.",
	})

	opts = ini.LoadOptions{
		// Do not error on nonexistent file to allow empty string as filename input
		Loose: true,
		// MySQL ini file can have boolean keys.
		AllowBooleanKeys: true,
		// Ignore the # character in the line to avoid password parsing failure when the MySQL password contains the # symbol
		IgnoreInlineComment: true,
		// Remove the first and last quotation marks
		UnescapeValueDoubleQuotes: true,
	}

	err error
)

type Config struct {
	Sections map[string]MySqlConfig
}

type MySqlConfig struct {
	User                  string `ini:"user"`
	Password              string `ini:"password"`
	Host                  string `ini:"host"`
	Port                  int    `ini:"port"`
	Socket                string `ini:"socket"`
	SslCa                 string `ini:"ssl-ca"`
	SslCert               string `ini:"ssl-cert"`
	SslKey                string `ini:"ssl-key"`
	TlsInsecureSkipVerify bool   `ini:"ssl-skip-verfication"` //nolint:misspell
	Tls                   string `ini:"tls"`
	EnableCleartextPlugin bool   `ini:"enable-cleartext-plugin"`
	TimeZone              string `ini:"time_zone"`
}

type MySqlConfigHandler struct {
	sync.RWMutex
	TlsInsecureSkipVerify bool
	Config                *Config
}

func (ch *MySqlConfigHandler) GetConfig() *Config {
	ch.RLock()
	defer ch.RUnlock()
	return ch.Config
}

func (ch *MySqlConfigHandler) ReloadConfig(filename string, mysqldAddress string, mysqldUser string, tlsInsecureSkipVerify bool, logger *slog.Logger) error {
	var host, port string
	defer func() {
		if err != nil {
			configReloadSuccess.Set(0)
		} else {
			configReloadSuccess.Set(1)
			configReloadSeconds.SetToCurrentTime()
		}
	}()

	cfg, err := ini.LoadSources(
		opts,
		[]byte("[client]\npassword = ${MYSQLD_EXPORTER_PASSWORD}\n"),
		filename,
	)
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", filename, err)
	}

	if host, port, err = net.SplitHostPort(mysqldAddress); err != nil {
		return fmt.Errorf("failed to parse address: %w", err)
	}

	if clientSection := cfg.Section("client"); clientSection != nil {
		if cfgHost := clientSection.Key("host"); cfgHost.String() == "" {
			cfgHost.SetValue(host)
		}
		if cfgPort := clientSection.Key("port"); cfgPort.String() == "" {
			cfgPort.SetValue(port)
		}
		if cfgUser := clientSection.Key("user"); cfgUser.String() == "" {
			cfgUser.SetValue(mysqldUser)
		}
	}

	cfg.ValueMapper = os.ExpandEnv
	config := &Config{}
	m := make(map[string]MySqlConfig)
	for _, sec := range cfg.Sections() {
		sectionName := sec.Name()

		if sectionName == "DEFAULT" {
			continue
		}

		mysqlcfg := &MySqlConfig{
			TlsInsecureSkipVerify: tlsInsecureSkipVerify,
		}

		err = sec.StrictMapTo(mysqlcfg)
		if err != nil {
			logger.Error("failed to parse config", "section", sectionName, "err", err)
			continue
		}
		if err := mysqlcfg.validateConfig(); err != nil {
			logger.Error("failed to validate config", "section", sectionName, "err", err)
			continue
		}

		m[sectionName] = *mysqlcfg
	}
	config.Sections = m
	if len(config.Sections) == 0 {
		return fmt.Errorf("no configuration found")
	}
	ch.Lock()
	ch.Config = config
	ch.Unlock()
	return nil
}

func (m MySqlConfig) validateConfig() error {
	if m.User == "" {
		return fmt.Errorf("no user specified in section or parent")
	}

	return nil
}

func (m MySqlConfig) FormDSN(target string) (string, error) {
	config := mysql.NewConfig()
	config.User = m.User
	config.Passwd = m.Password
	config.Net = "tcp"
	if target == "" {
		if m.Socket == "" {
			host := "127.0.0.1"
			if m.Host != "" {
				host = m.Host
			}
			port := "3306"
			if m.Port != 0 {
				port = strconv.Itoa(m.Port)
			}
			config.Addr = net.JoinHostPort(host, port)
		} else {
			config.Net = "unix"
			config.Addr = m.Socket
		}
	} else if prefix := "unix://"; strings.HasPrefix(target, prefix) {
		config.Net = "unix"
		config.Addr = target[len(prefix):]
	} else {
		if _, _, err = net.SplitHostPort(target); err != nil {
			return "", fmt.Errorf("failed to parse target: %s", err)
		}
		config.Addr = target
	}

	if m.TlsInsecureSkipVerify {
		config.TLSConfig = "skip-verify"
	} else {
		config.TLSConfig = m.Tls
		if m.SslCa != "" {
			if err := m.CustomizeTLS(); err != nil {
				err = fmt.Errorf("failed to register a custom TLS configuration for mysql dsn: %w", err)
				return "", err
			}
			config.TLSConfig = "custom"
		}
	}
	if m.EnableCleartextPlugin {
		config.AllowCleartextPasswords = true
	}
	if m.TimeZone != "" {
		// Applied by the driver as `SET time_zone=<value>` on every new connection.
		// go-ini has already stripped the surrounding quotes from the my.cnf value,
		// so it arrives here bare (e.g. +00:00 or UTC) and must be quoted, or the
		// SET is invalid syntax; do it here rather than relying on the user
		// pre-quoting the my.cnf value.
		config.Params = map[string]string{"time_zone": quoteTimeZone(m.TimeZone)}
	}

	return config.FormatDSN(), nil
}

// quoteTimeZone returns the time zone as a single-quoted SQL literal so the
// driver issues a valid SET time_zone='<value>'. Any surrounding quotes the
// value still carries are removed first (so a pre-quoted value is not
// double-wrapped) and interior single quotes are doubled so the literal cannot
// be broken out of.
func quoteTimeZone(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		first, last := v[0], v[len(v)-1]
		if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
			v = v[1 : len(v)-1]
		}
	}
	return "'" + strings.ReplaceAll(v, "'", "''") + "'"
}

func (m MySqlConfig) CustomizeTLS() error {
	var tlsCfg tls.Config
	caBundle := x509.NewCertPool()
	pemCA, err := os.ReadFile(m.SslCa)
	if err != nil {
		return err
	}
	if ok := caBundle.AppendCertsFromPEM(pemCA); ok {
		tlsCfg.RootCAs = caBundle
	} else {
		return fmt.Errorf("failed to parse pem-encoded CA certificates from %s", m.SslCa)
	}
	if m.SslCert != "" && m.SslKey != "" {
		certPairs := make([]tls.Certificate, 0, 1)
		keypair, err := tls.LoadX509KeyPair(m.SslCert, m.SslKey)
		if err != nil {
			return fmt.Errorf("failed to parse pem-encoded SSL cert %s or SSL key %s: %w",
				m.SslCert, m.SslKey, err)
		}
		certPairs = append(certPairs, keypair)
		tlsCfg.Certificates = certPairs
	}
	tlsCfg.InsecureSkipVerify = m.TlsInsecureSkipVerify
	mysql.RegisterTLSConfig("custom", &tlsCfg)
	return nil
}
