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
)

// testTLSFiles holds paths to a throwaway CA certificate and a client key pair
// signed by it. CustomizeTLS only parses these, so they are never used for a
// real handshake.
type testTLSFiles struct {
	ca   string
	cert string
	key  string
}

// writeTestTLSFiles generates a self-signed CA and a client key pair signed by
// it, writing all three PEM files into the test's temporary directory.
func writeTestTLSFiles(t *testing.T) testTLSFiles {
	t.Helper()

	dir := t.TempDir()
	notBefore := time.Now().Add(-time.Hour)
	notAfter := notBefore.Add(24 * time.Hour)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %s", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mysqld_exporter test CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create CA certificate: %s", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %s", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %s", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mysqld_exporter test client"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create client certificate: %s", err)
	}
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatalf("failed to marshal client key: %s", err)
	}

	files := testTLSFiles{
		ca:   filepath.Join(dir, "ca.pem"),
		cert: filepath.Join(dir, "client-cert.pem"),
		key:  filepath.Join(dir, "client-key.pem"),
	}
	writePEM(t, files.ca, "CERTIFICATE", caDER)
	writePEM(t, files.cert, "CERTIFICATE", clientDER)
	writePEM(t, files.key, "EC PRIVATE KEY", clientKeyDER)

	return files
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()

	encoded := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if encoded == nil {
		t.Fatalf("failed to pem-encode %s", path)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("failed to write %s: %s", path, err)
	}
}

// writeGarbage writes a file that is readable but is not valid PEM.
func writeGarbage(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatalf("failed to write %s: %s", path, err)
	}
	return path
}

// TestCustomizeTLS covers each way CustomizeTLS can succeed or fail.
func TestCustomizeTLS(t *testing.T) {
	files := writeTestTLSFiles(t)
	missing := filepath.Join(t.TempDir(), "no-such-ca.pem")

	for _, tc := range []struct {
		name    string
		config  MySqlConfig
		wantErr string
	}{
		{
			name:   "ca only",
			config: MySqlConfig{SslCa: files.ca},
		},
		{
			name:   "ca with client key pair",
			config: MySqlConfig{SslCa: files.ca, SslCert: files.cert, SslKey: files.key},
		},
		{
			// Only a complete pair is loaded, so a cert without a key is
			// silently ignored rather than rejected.
			name:   "cert without key is ignored",
			config: MySqlConfig{SslCa: files.ca, SslCert: files.cert},
		},
		{
			name:   "key without cert is ignored",
			config: MySqlConfig{SslCa: files.ca, SslKey: files.key},
		},
		{
			name:    "unreadable ca",
			config:  MySqlConfig{SslCa: missing},
			wantErr: "no such file or directory",
		},
		{
			name:    "ca is not pem",
			config:  MySqlConfig{SslCa: writeGarbage(t, "garbage-ca.pem")},
			wantErr: "failed to parse pem-encoded CA certificates from",
		},
		{
			name:    "client cert is not pem",
			config:  MySqlConfig{SslCa: files.ca, SslCert: writeGarbage(t, "garbage-cert.pem"), SslKey: files.key},
			wantErr: "failed to parse pem-encoded SSL cert",
		},
		{
			name:    "client key is not pem",
			config:  MySqlConfig{SslCa: files.ca, SslCert: files.cert, SslKey: writeGarbage(t, "garbage-key.pem")},
			wantErr: "failed to parse pem-encoded SSL cert",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.CustomizeTLS()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %s", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestFormDSNWithSslCa covers the ssl-ca branch of FormDSN. The registered
// configuration is read back through the driver, which resolves tls=custom to
// the tls.Config CustomizeTLS registered.
func TestFormDSNWithSslCa(t *testing.T) {
	files := writeTestTLSFiles(t)

	m := MySqlConfig{
		User:     "usr",
		Password: "pwd",
		Host:     "server1",
		Port:     3306,
		SslCa:    files.ca,
		SslCert:  files.cert,
		SslKey:   files.key,
		// Ignored while forming the DSN, but CustomizeTLS copies it into the
		// registered tls.Config.
		Tls: "true",
	}

	dsn, err := m.FormDSN("")
	if err != nil {
		t.Fatalf("error forming dsn: %s", err)
	}
	if want := "usr:pwd@tcp(server1:3306)/?tls=custom"; dsn != want {
		t.Fatalf("dsn: got %q, want %q", dsn, want)
	}

	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("driver cannot parse dsn %q: %s", dsn, err)
	}
	if cfg.TLS == nil {
		t.Fatal("tls=custom did not resolve to a registered tls.Config")
	}
	if cfg.TLS.RootCAs == nil {
		t.Error("registered tls.Config has no root CAs")
	}
	if got := len(cfg.TLS.Certificates); got != 1 {
		t.Errorf("registered client certificates: got %d, want 1", got)
	}
	if cfg.TLS.InsecureSkipVerify {
		t.Error("registered tls.Config skips verification")
	}
}

// TestFormDSNSslCaError covers the failure to register the custom TLS
// configuration.
func TestFormDSNSslCaError(t *testing.T) {
	m := MySqlConfig{
		User:  "usr",
		Host:  "server1",
		Port:  3306,
		SslCa: writeGarbage(t, "garbage-ca.pem"),
	}

	dsn, err := m.FormDSN("")
	if err == nil {
		t.Fatalf("expected an error, got dsn %q", dsn)
	}
	if want := "failed to register a custom TLS configuration for mysql dsn: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error %q does not start with %q", err.Error(), want)
	}
	if dsn != "" {
		t.Errorf("dsn: got %q, want an empty string", dsn)
	}
}

// TestFormDSNSslCaIgnoredWhenSkipVerify pins that TlsInsecureSkipVerify wins
// over ssl-ca: no custom configuration is registered at all, so an unusable CA
// file is never even read.
func TestFormDSNSslCaIgnoredWhenSkipVerify(t *testing.T) {
	m := MySqlConfig{
		User:                  "usr",
		Password:              "pwd",
		Host:                  "server1",
		Port:                  3306,
		SslCa:                 writeGarbage(t, "garbage-ca.pem"),
		TlsInsecureSkipVerify: true,
	}

	dsn, err := m.FormDSN("")
	if err != nil {
		t.Fatalf("error forming dsn: %s", err)
	}
	if want := "usr:pwd@tcp(server1:3306)/?tls=skip-verify"; dsn != want {
		t.Errorf("dsn: got %q, want %q", dsn, want)
	}
}
