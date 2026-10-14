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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/common/promslog"
)

// Example credentials from the AWS SigV4 documentation. They are syntactically
// valid, which is all BuildAuthToken needs -- nothing here talks to AWS.
const (
	testAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	testSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// awsEnvKeys is every variable the SDK's default config chain reads that could
// make these tests depend on the developer's shell or on the CI runner's role.
var awsEnvKeys = []string{
	"AWS_ACCESS_KEY_ID",
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_PROFILE",
	"AWS_DEFAULT_PROFILE",
	"AWS_REGION",
	"AWS_DEFAULT_REGION",
	"AWS_ROLE_ARN",
	"AWS_ROLE_SESSION_NAME",
	"AWS_WEB_IDENTITY_TOKEN_FILE",
	"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
	"AWS_CONTAINER_CREDENTIALS_FULL_URI",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN",
	"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
	"AWS_MAX_ATTEMPTS",
	"AWS_RETRY_MODE",
	"AWS_USE_DUALSTACK_ENDPOINT",
	"AWS_USE_FIPS_ENDPOINT",
	"AWS_REQUEST_CHECKSUM_CALCULATION",
	"AWS_RESPONSE_CHECKSUM_VALIDATION",
	"AWS_ACCOUNT_ID_ENDPOINT_MODE",
}

// isolateAWSEnv makes LoadDefaultConfig deterministic and offline: the shared
// config and credentials files point at a path that does not exist, IMDS is
// switched off so the credential chain cannot reach the network, and every
// other AWS_* variable is dropped.
func isolateAWSEnv(t *testing.T) {
	t.Helper()

	missing := filepath.Join(t.TempDir(), "no-such-aws-file")
	t.Setenv("AWS_CONFIG_FILE", missing)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", missing)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	for _, key := range awsEnvKeys {
		unsetEnv(t, key)
	}
}

// unsetEnv removes key for the duration of the test. t.Setenv captures the
// original value -- and whether it was set at all -- before we delete it, so
// the cleanup it registers still restores the environment exactly.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("failed to unset %s: %s", key, err)
	}
}

// staticAWSCreds gives the default credential chain a resolvable set of
// credentials, so BuildAuthToken can sign without any provider I/O.
func staticAWSCreds(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", testAccessKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", testSecretAccessKey)
}

// rdsAuthToken splits an RDS IAM auth token into the endpoint it was signed
// for and its query parameters, failing the test if it is not shaped like one.
// A token looks like "host:port?Action=connect&...&X-Amz-Signature=...".
func rdsAuthToken(t *testing.T, token string) (string, url.Values) {
	t.Helper()

	endpoint, rawQuery, found := strings.Cut(token, "?")
	if !found {
		t.Fatalf("auth token %q has no query string", token)
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatalf("failed to parse auth token query %q: %s", rawQuery, err)
	}
	return endpoint, values
}

// TestFormDSNAwsIamAuth covers the happy path: the signed token replaces
// whatever password the section carried, and it is signed for the address the
// DSN actually connects to, for the configured user and region.
func TestFormDSNAwsIamAuth(t *testing.T) {
	isolateAWSEnv(t)
	staticAWSCreds(t)
	// A different region in the environment must not win over the section's.
	t.Setenv("AWS_REGION", "us-west-2")

	m := MySqlConfig{
		User:       "iamuser",
		Password:   "should-be-replaced",
		Host:       "rds.example.com",
		Port:       3306,
		AwsIamAuth: true,
		AwsRegion:  "eu-central-1",
	}

	dsn, err := m.FormDSN("")
	if err != nil {
		t.Fatalf("error forming dsn: %s", err)
	}

	// The token contains "?", "&" and ":", so the DSN must still be parseable
	// by the driver that will receive it.
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("driver cannot parse dsn %q: %s", dsn, err)
	}
	if cfg.User != "iamuser" {
		t.Errorf("user: got %q, want %q", cfg.User, "iamuser")
	}
	if cfg.Net != "tcp" {
		t.Errorf("net: got %q, want %q", cfg.Net, "tcp")
	}
	if cfg.Addr != "rds.example.com:3306" {
		t.Errorf("addr: got %q, want %q", cfg.Addr, "rds.example.com:3306")
	}
	if cfg.Passwd == "should-be-replaced" {
		t.Error("password was not replaced by an IAM auth token")
	}

	endpoint, values := rdsAuthToken(t, cfg.Passwd)
	if endpoint != "rds.example.com:3306" {
		t.Errorf("token endpoint: got %q, want %q", endpoint, "rds.example.com:3306")
	}
	if got := values.Get("Action"); got != "connect" {
		t.Errorf("token Action: got %q, want %q", got, "connect")
	}
	if got := values.Get("DBUser"); got != "iamuser" {
		t.Errorf("token DBUser: got %q, want %q", got, "iamuser")
	}
	if got := values.Get("X-Amz-Expires"); got != "900" {
		t.Errorf("token X-Amz-Expires: got %q, want %q", got, "900")
	}
	if got := values.Get("X-Amz-Algorithm"); got != "AWS4-HMAC-SHA256" {
		t.Errorf("token X-Amz-Algorithm: got %q, want %q", got, "AWS4-HMAC-SHA256")
	}
	if values.Get("X-Amz-Signature") == "" {
		t.Error("token is not signed: X-Amz-Signature is empty")
	}
	// Credential scope is "<key>/<date>/<region>/rds-db/aws4_request", so it
	// proves the section's region -- not AWS_REGION -- was signed for.
	credential := values.Get("X-Amz-Credential")
	if !strings.HasPrefix(credential, testAccessKeyID+"/") {
		t.Errorf("token X-Amz-Credential %q does not start with the configured access key", credential)
	}
	if !strings.HasSuffix(credential, "/eu-central-1/rds-db/aws4_request") {
		t.Errorf("token X-Amz-Credential %q was not scoped to eu-central-1/rds-db", credential)
	}
}

// TestFormDSNAwsIamAuthSignsTarget pins that the token is signed for the
// resolved target address rather than the section's own host and port.
func TestFormDSNAwsIamAuthSignsTarget(t *testing.T) {
	isolateAWSEnv(t)
	staticAWSCreds(t)

	m := MySqlConfig{
		User:       "iamuser",
		Host:       "rds.example.com",
		Port:       3306,
		AwsIamAuth: true,
		AwsRegion:  "eu-central-1",
	}

	dsn, err := m.FormDSN("replica.example.com:5000")
	if err != nil {
		t.Fatalf("error forming dsn: %s", err)
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("driver cannot parse dsn %q: %s", dsn, err)
	}
	if cfg.Addr != "replica.example.com:5000" {
		t.Errorf("addr: got %q, want %q", cfg.Addr, "replica.example.com:5000")
	}

	endpoint, _ := rdsAuthToken(t, cfg.Passwd)
	if endpoint != "replica.example.com:5000" {
		t.Errorf("token endpoint: got %q, want %q", endpoint, "replica.example.com:5000")
	}
}

// TestFormDSNAwsIamAuthMissingRegion covers the guard that rejects IAM
// authentication without a region, before any AWS call is attempted.
func TestFormDSNAwsIamAuthMissingRegion(t *testing.T) {
	isolateAWSEnv(t)
	staticAWSCreds(t)
	// Even a usable region in the environment must not satisfy the guard.
	t.Setenv("AWS_REGION", "eu-central-1")

	m := MySqlConfig{
		User:       "iamuser",
		Host:       "rds.example.com",
		Port:       3306,
		AwsIamAuth: true,
	}

	dsn, err := m.FormDSN("")
	if err == nil {
		t.Fatalf("expected an error, got dsn %q", dsn)
	}
	if want := "aws region must be specified for IAM authentication"; err.Error() != want {
		t.Errorf("error: got %q, want %q", err.Error(), want)
	}
	if dsn != "" {
		t.Errorf("dsn: got %q, want an empty string", dsn)
	}
}

// TestFormDSNAwsIamAuthLoadConfigError covers the failure to load the AWS
// config, provoked by a value the SDK cannot parse.
func TestFormDSNAwsIamAuthLoadConfigError(t *testing.T) {
	isolateAWSEnv(t)
	staticAWSCreds(t)
	t.Setenv("AWS_MAX_ATTEMPTS", "not-a-number")

	m := MySqlConfig{
		User:       "iamuser",
		Host:       "rds.example.com",
		Port:       3306,
		AwsIamAuth: true,
		AwsRegion:  "eu-central-1",
	}

	dsn, err := m.FormDSN("")
	if err == nil {
		t.Fatalf("expected an error, got dsn %q", dsn)
	}
	if want := "failed to load AWS config for IAM authentication: "; !strings.HasPrefix(err.Error(), want) {
		t.Errorf("error %q does not start with %q", err.Error(), want)
	}
	if !strings.Contains(err.Error(), "AWS_MAX_ATTEMPTS") {
		t.Errorf("error %q does not mention the offending variable", err.Error())
	}
	if dsn != "" {
		t.Errorf("dsn: got %q, want an empty string", dsn)
	}
}

// TestFormDSNAwsIamAuthBuildTokenError covers the failure to build the token,
// which is where an unusable endpoint or an unresolvable credential lands.
func TestFormDSNAwsIamAuthBuildTokenError(t *testing.T) {
	for _, tc := range []struct {
		name        string
		creds       bool
		config      MySqlConfig
		target      string
		wantDetails string
	}{
		{
			// A socket address has no port, which BuildAuthToken requires,
			// so IAM authentication cannot work over a UNIX socket.
			name:  "unix socket target has no port",
			creds: true,
			config: MySqlConfig{
				User:       "iamuser",
				AwsIamAuth: true,
				AwsRegion:  "eu-central-1",
			},
			target:      "unix:///run/mysqld/mysqld.sock",
			wantDetails: "the provided endpoint is missing a port",
		},
		{
			name:  "socket from config has no port",
			creds: true,
			config: MySqlConfig{
				User:       "iamuser",
				Socket:     "/run/mysqld/mysqld.sock",
				AwsIamAuth: true,
				AwsRegion:  "eu-central-1",
			},
			wantDetails: "the provided endpoint is missing a port",
		},
		{
			name:  "no credentials to sign with",
			creds: false,
			config: MySqlConfig{
				User:       "iamuser",
				Host:       "rds.example.com",
				Port:       3306,
				AwsIamAuth: true,
				AwsRegion:  "eu-central-1",
			},
			wantDetails: "failed to refresh cached credentials",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateAWSEnv(t)
			if tc.creds {
				staticAWSCreds(t)
			}

			dsn, err := tc.config.FormDSN(tc.target)
			if err == nil {
				t.Fatalf("expected an error, got dsn %q", dsn)
			}
			if want := "failed to build auth token for IAM authentication: "; !strings.HasPrefix(err.Error(), want) {
				t.Errorf("error %q does not start with %q", err.Error(), want)
			}
			if !strings.Contains(err.Error(), tc.wantDetails) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantDetails)
			}
			if dsn != "" {
				t.Errorf("dsn: got %q, want an empty string", dsn)
			}
		})
	}
}

// TestFormDSNAwsIamAuthDisabled pins that a section keeps its static password
// when IAM authentication is off, even with a region configured, and that no
// AWS credentials are needed to form the DSN.
func TestFormDSNAwsIamAuthDisabled(t *testing.T) {
	isolateAWSEnv(t)

	m := MySqlConfig{
		User:      "iamuser",
		Password:  "staticpassword",
		Host:      "rds.example.com",
		Port:      3306,
		AwsRegion: "eu-central-1",
	}

	dsn, err := m.FormDSN("")
	if err != nil {
		t.Fatalf("error forming dsn: %s", err)
	}
	if want := "iamuser:staticpassword@tcp(rds.example.com:3306)/"; dsn != want {
		t.Errorf("dsn: got %q, want %q", dsn, want)
	}
}

// TestReloadConfigAwsIam covers parsing of the aws-iam-auth and aws-region
// keys out of a my.cnf section.
func TestReloadConfigAwsIam(t *testing.T) {
	c := MySqlConfigHandler{Config: &Config{}}
	if err := c.ReloadConfig("testdata/client_aws_iam.cnf", "localhost:3306", "", false, promslog.NewNopLogger()); err != nil {
		t.Fatalf("error reloading config: %s", err)
	}
	cfg := c.GetConfig()

	for _, tc := range []struct {
		section       string
		wantIamAuth   bool
		wantRegion    string
		wantPassword  string
		wantCleartext bool
		wantTls       string
	}{
		{section: "client_aws_iam", wantIamAuth: true, wantRegion: "eu-central-1"},
		{section: "client_aws_iam_no_region", wantIamAuth: true},
		{section: "client_aws_iam_disabled", wantRegion: "eu-central-1", wantPassword: "staticpassword"},
		{section: "client_aws_iam_rds", wantIamAuth: true, wantRegion: "eu-central-1", wantCleartext: true, wantTls: "true"},
	} {
		t.Run(tc.section, func(t *testing.T) {
			section, ok := cfg.Sections[tc.section]
			if !ok {
				t.Fatalf("section %q is missing from the parsed config", tc.section)
			}
			if section.AwsIamAuth != tc.wantIamAuth {
				t.Errorf("AwsIamAuth: got %v, want %v", section.AwsIamAuth, tc.wantIamAuth)
			}
			if section.AwsRegion != tc.wantRegion {
				t.Errorf("AwsRegion: got %q, want %q", section.AwsRegion, tc.wantRegion)
			}
			if section.Password != tc.wantPassword {
				t.Errorf("Password: got %q, want %q", section.Password, tc.wantPassword)
			}
			if section.EnableCleartextPlugin != tc.wantCleartext {
				t.Errorf("EnableCleartextPlugin: got %v, want %v", section.EnableCleartextPlugin, tc.wantCleartext)
			}
			if section.Tls != tc.wantTls {
				t.Errorf("Tls: got %q, want %q", section.Tls, tc.wantTls)
			}
		})
	}
}

// TestFormDSNAwsIamAuthFromConfigFile is the end-to-end shape RDS actually
// needs: an IAM token as the password, TLS on, and the cleartext plugin
// allowed so the long token reaches the server.
func TestFormDSNAwsIamAuthFromConfigFile(t *testing.T) {
	isolateAWSEnv(t)
	staticAWSCreds(t)

	c := MySqlConfigHandler{Config: &Config{}}
	if err := c.ReloadConfig("testdata/client_aws_iam.cnf", "localhost:3306", "", false, promslog.NewNopLogger()); err != nil {
		t.Fatalf("error reloading config: %s", err)
	}
	section := c.GetConfig().Sections["client_aws_iam_rds"]

	dsn, err := section.FormDSN("")
	if err != nil {
		t.Fatalf("error forming dsn: %s", err)
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("driver cannot parse dsn %q: %s", dsn, err)
	}
	if !cfg.AllowCleartextPasswords {
		t.Error("allowCleartextPasswords is not set")
	}
	if cfg.TLSConfig != "true" {
		t.Errorf("tls: got %q, want %q", cfg.TLSConfig, "true")
	}

	endpoint, values := rdsAuthToken(t, cfg.Passwd)
	if endpoint != "rds.example.com:3306" {
		t.Errorf("token endpoint: got %q, want %q", endpoint, "rds.example.com:3306")
	}
	if got := values.Get("DBUser"); got != "iamuser" {
		t.Errorf("token DBUser: got %q, want %q", got, "iamuser")
	}
}

// TestFormDSNAwsIamAuthWithSkipVerify pins that IAM authentication composes
// with TlsInsecureSkipVerify, which takes a different branch of the TLS setup
// that runs just before the token is built.
func TestFormDSNAwsIamAuthWithSkipVerify(t *testing.T) {
	isolateAWSEnv(t)
	staticAWSCreds(t)

	m := MySqlConfig{
		User:                  "iamuser",
		Host:                  "rds.example.com",
		Port:                  3306,
		TlsInsecureSkipVerify: true,
		AwsIamAuth:            true,
		AwsRegion:             "eu-central-1",
	}

	dsn, err := m.FormDSN("")
	if err != nil {
		t.Fatalf("error forming dsn: %s", err)
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("driver cannot parse dsn %q: %s", dsn, err)
	}
	if cfg.TLSConfig != "skip-verify" {
		t.Errorf("tls: got %q, want %q", cfg.TLSConfig, "skip-verify")
	}
	if _, values := rdsAuthToken(t, cfg.Passwd); values.Get("X-Amz-Signature") == "" {
		t.Error("token is not signed: X-Amz-Signature is empty")
	}
}
