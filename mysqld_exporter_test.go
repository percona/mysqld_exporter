package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-kit/log"

	"github.com/smartystreets/goconvey/convey"
)

func TestParseMycnf(t *testing.T) {
	const (
		tcpConfig = `
			[client]
			user = root
			password = abc123
		`
		tcpConfig2 = `
			[client]
			user = root
			password = abc123
			port = 3308
		`
		clientAuthConfig = `
			[client]
			user = root
			port = 3308
			ssl-ca = ca.crt
 			ssl-cert = tls.crt
 			ssl-key = tls.key
		`
		socketConfig = `
			[client]
			user = user
			password = pass
			socket = /var/lib/mysql/mysql.sock
		`
		socketConfig2 = `
			[client]
			user = dude
			password = nopassword
			# host and port will not be used because of socket presence
			host = 1.2.3.4
			port = 3307
			socket = /var/lib/mysql/mysql.sock
		`
		remoteConfig = `
			[client]
			user = dude
			password = nopassword
			host = 1.2.3.4
			port = 3307
		`
		ignoreBooleanKeys = `
			[client]
			user = root
			password = abc123

			[mysql]
			skip-auto-rehash
		`
		badConfig = `
			[client]
			user = root
		`
		badConfig2 = `
			[client]
			password = abc123
			socket = /var/lib/mysql/mysql.sock
		`
		badConfig3 = `
			[hello]
			world = ismine
		`
		badConfig4 = `[hello`
	)
	logger := log.NewNopLogger()
	convey.Convey("Various .my.cnf configurations", t, func() {
		convey.Convey("Local tcp connection", func() {
			dsn, _ := parseMycnf([]byte(tcpConfig), logger)
			convey.So(dsn, convey.ShouldEqual, "root:abc123@tcp(localhost:3306)/")
		})
		convey.Convey("Local tcp connection on non-default port", func() {
			dsn, _ := parseMycnf([]byte(tcpConfig2), logger)
			convey.So(dsn, convey.ShouldEqual, "root:abc123@tcp(localhost:3308)/")
		})
		convey.Convey("Authentication with client certificate and no password", func() {
			dsn, _ := parseMycnf([]byte(clientAuthConfig), logger)
			convey.So(dsn, convey.ShouldEqual, "root@tcp(localhost:3308)/")
		})
		convey.Convey("Socket connection", func() {
			dsn, _ := parseMycnf([]byte(socketConfig), logger)
			convey.So(dsn, convey.ShouldEqual, "user:pass@unix(/var/lib/mysql/mysql.sock)/")
		})
		convey.Convey("Socket connection ignoring defined host", func() {
			dsn, _ := parseMycnf([]byte(socketConfig2), logger)
			convey.So(dsn, convey.ShouldEqual, "dude:nopassword@unix(/var/lib/mysql/mysql.sock)/")
		})
		convey.Convey("Remote connection", func() {
			dsn, _ := parseMycnf([]byte(remoteConfig), logger)
			convey.So(dsn, convey.ShouldEqual, "dude:nopassword@tcp(1.2.3.4:3307)/")
		})
		convey.Convey("Ignore boolean keys", func() {
			dsn, _ := parseMycnf([]byte(ignoreBooleanKeys), logger)
			convey.So(dsn, convey.ShouldEqual, "root:abc123@tcp(localhost:3306)/")
		})
		convey.Convey("Missed user", func() {
			_, err := parseMycnf([]byte(badConfig), logger)
			convey.So(err, convey.ShouldBeError, fmt.Errorf("password or ssl-key should be specified under [client] in %s", badConfig))
		})
		convey.Convey("Missed password", func() {
			_, err := parseMycnf([]byte(badConfig2), logger)
			convey.So(err, convey.ShouldBeError, fmt.Errorf("no user specified under [client] in %s", badConfig2))
		})
		convey.Convey("No [client] section", func() {
			_, err := parseMycnf([]byte(badConfig3), logger)
			convey.So(err, convey.ShouldBeError, fmt.Errorf("no user specified under [client] in %s", badConfig3))
		})
		convey.Convey("Invalid config", func() {
			_, err := parseMycnf([]byte(badConfig4), logger)
			convey.So(err, convey.ShouldBeError, fmt.Errorf("failed reading ini file: unclosed section: %s", badConfig4))
		})
	})
}

func TestSSL(t *testing.T) {
	if _, err := os.Stat(filepath.Join(os.TempDir(), "client-cert.pem")); os.IsNotExist(err) {
		t.Skip("Use make env-up to run this test")
	}

	db, err := newDB("root:@tcp(127.0.0.1:3306)/")
	convey.Convey("Local tcp connection", t, func() {
		convey.So(err, convey.ShouldBeNil)
	})

	convey.Convey("Create test user", t, func() {
		_, err = db.Exec("CREATE USER 'fry'@'%' IDENTIFIED BY 'pass' REQUIRE X509")
		convey.So(err, convey.ShouldBeNil)

		_, err = db.Exec("GRANT ALL PRIVILEGES ON *.* TO 'fry'@'%' WITH GRANT OPTION")
		convey.So(err, convey.ShouldBeNil)

		_, err = db.Exec("FLUSH PRIVILEGES")
		convey.So(err, convey.ShouldBeNil)
	})

	sslCA := filepath.Join(os.TempDir(), "ca.pem")
	sslCert := filepath.Join(os.TempDir(), "client-cert.pem")
	sslKey := filepath.Join(os.TempDir(), "client-key.pem")
	skipVerify := true
	mysqlSSLSkipVerify = &skipVerify

	convey.Convey("TestSSL connection", t, func() {
		convey.Convey("Local tcp connection", func() {
			convey.So(customizeTLS(sslCA, sslCert, sslKey), convey.ShouldBeNil)
		})

		db, err := newDB("fry:pass@tcp(127.0.0.1:3306)/?tls=custom")
		convey.So(err, convey.ShouldBeNil)
		convey.So(db, convey.ShouldNotBeNil)
		convey.So(db.Ping(), convey.ShouldBeNil)
	})

	convey.Convey("Drop test user", t, func() {
		_, err = db.Exec("DROP USER 'fry'@'%'")
		convey.So(err, convey.ShouldBeNil)
	})
}

// bin stores information about path of executable and attached port
type bin struct {
	path string
	port int
}

// TestBin builds, runs and tests binary.
func TestBin(t *testing.T) {
	var err error
	binName := "mysqld_exporter"

	binDir, err := ioutil.TempDir("/tmp", binName+"-test-bindir-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := os.RemoveAll(binDir)
		if err != nil {
			t.Fatal(err)
		}
	}()

	importpath := "github.com/prometheus/common"
	path := binDir + "/" + binName
	xVariables := map[string]string{
		importpath + "/version.Version":  "gotest-version",
		importpath + "/version.Branch":   "gotest-branch",
		importpath + "/version.Revision": "gotest-revision",
	}
	var ldflags []string
	for x, value := range xVariables {
		ldflags = append(ldflags, fmt.Sprintf("-X %s=%s", x, value))
	}
	cmd := exec.Command( // nolint
		"go",
		"build",
		"-o",
		path,
		"-ldflags",
		strings.Join(ldflags, " "),
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		t.Fatalf("Failed to build: %s", err)
	}

	tests := []func(*testing.T, bin){
		testLandingPage,
		testVersion,
		testDefaultGatherer,
		testDebugEndpoints,
	}

	portStart := 56000
	t.Run(binName, func(t *testing.T) {
		for _, f := range tests {
			f := f // capture range variable
			fName := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
			portStart++
			data := bin{
				path: path,
				port: portStart,
			}
			t.Run(fName, func(t *testing.T) {
				t.Parallel()
				f(t, data)
			})
		}
	})
}

func TestCustomTLSinDSN(t *testing.T) {
	testCases := []struct {
		dsn  string
		want string
	}{
		{
			dsn:  "user:pass@tcp(127.0.0.1:3306)/",
			want: "user:pass@tcp(127.0.0.1:3306)/?tls=custom",
		},
		{
			dsn:  "user:pass@tcp(127.0.0.1:3306)/?param1=val1",
			want: "user:pass@tcp(127.0.0.1:3306)/?tls=custom&param1=val1",
		},
		// sessionSettingsParam params are being added if exporterLogSlowFilter is set
		// This test is not a real case. Upstream is manually adding the sessionSettingsParam
		// using strings.Join while the driver would parse the dns and convert the , to %2C
		{
			dsn:  "user:pass@tcp(127.0.0.1:3306)/?" + sessionSettingsParam,
			want: "user:pass@tcp(127.0.0.1:3306)/?tls=custom&" + strings.ReplaceAll(sessionSettingsParam, ",", "%2C"),
		},
	}

	for _, tc := range testCases {
		dsn, err := setTLSConfig(tc.dsn)

		convey.Convey("Add TLS=custom", t, func() {
			convey.So(err, convey.ShouldBeNil)
			convey.So(dsn, convey.ShouldEqual, tc.want)
		})
	}
}

func testVersion(t *testing.T, data bin) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cmd := exec.CommandContext( // nolint
		ctx,
		data.path,
		"--version",
		"--web.listen-address", fmt.Sprintf(":%d", data.port),
	)

	b := &bytes.Buffer{}
	cmd.Stdout = b
	cmd.Stderr = b

	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}

	expectedRegexp := `mysqld_exporter, version gotest-version \(branch: gotest-branch, revision: gotest-revision\)
  build user:
  build date:
  go version:
  platform:
`

	expectedScanner := bufio.NewScanner(bytes.NewBufferString(expectedRegexp))
	defer func() {
		if err := expectedScanner.Err(); err != nil {
			t.Fatal(err)
		}
	}()

	gotScanner := bufio.NewScanner(b)
	defer func() {
		if err := gotScanner.Err(); err != nil {
			t.Fatal(err)
		}
	}()

	for gotScanner.Scan() {
		if !expectedScanner.Scan() {
			t.Fatalf("didn't expected more data but got '%s'", gotScanner.Text())
		}
		ok, err := regexp.MatchString(expectedScanner.Text(), gotScanner.Text())
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("'%s' does not match regexp '%s'", gotScanner.Text(), expectedScanner.Text())
		}
	}

	if expectedScanner.Scan() {
		t.Errorf("expected '%s' but didn't got more data", expectedScanner.Text())
	}
}

func testLandingPage(t *testing.T, data bin) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Run exporter.
	cmd := exec.CommandContext( // nolint
		ctx,
		data.path,
		"--web.listen-address", fmt.Sprintf(":%d", data.port),
	)
	cmd.Env = append(os.Environ(), "DATA_SOURCE_NAME=127.0.0.1:3306")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()

	// Get the main page.
	urlToGet := fmt.Sprintf("http://127.0.0.1:%d", data.port)
	body, err := waitForBody(urlToGet)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	expected := `<html>
<head><title>MySQLd exporter</title></head>
<body>
<h1>MySQL 3-in-1 exporter</h1>
<ul>
	<li><a href="/metrics-hr">high-res metrics</a></li>
	<li><a href="/metrics-mr">medium-res metrics</a></li>
	<li><a href="/metrics-lr">low-res metrics</a></li>
</ul>
<h1>MySQL exporter</h1>
<ul>
	<li><a href="/metrics">all metrics</a></li>
</ul>
</body>
</html>
`
	if got != expected {
		t.Fatalf("got '%s' but expected '%s'", got, expected)
	}
}

func testDefaultGatherer(t *testing.T, data bin) {
	metricPath := "/metrics"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext( // nolint
		ctx,
		data.path,
		"--web.telemetry-path", metricPath,
		"--web.listen-address", fmt.Sprintf(":%d", data.port),
	)
	cmd.Env = append(os.Environ(), "DATA_SOURCE_NAME=127.0.0.1:3306")

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()

	const resolution = "hr"
	body, err := waitForBody(fmt.Sprintf("http://127.0.0.1:%d%s-%s", data.port, metricPath, resolution))
	if err != nil {
		t.Fatalf("unable to get metrics for '%s' resolution: %s", resolution, err)
	}
	got := string(body)

	metricsPrefixes := []string{
		"go_gc_duration_seconds",
		"go_goroutines",
		"go_memstats",
	}

	for _, prefix := range metricsPrefixes {
		if !strings.Contains(got, prefix) {
			t.Fatalf("no metric starting with %s in resolution %s", prefix, resolution)
		}
	}
}

func testDebugEndpoints(t *testing.T, data bin) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext( // nolint
		ctx,
		data.path,
		"--web.listen-address", fmt.Sprintf(":%d", data.port),
	)
	cmd.Env = append(os.Environ(), "DATA_SOURCE_NAME=127.0.0.1:3306")

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	defer cmd.Process.Kill()

	body, err := waitForBody(fmt.Sprintf("http://127.0.0.1:%d/debug/vars", data.port))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err = json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m["cmdline"].([]interface{})[2] != fmt.Sprintf(":%d", data.port) {
		t.Fatalf("%#v", m["cmdline"])
	}

	body, err = waitForBody(fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/", data.port))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte("Types of profiles available")) {
		t.Fatalf("No pprof page at:\n%s", body)
	}
}

// waitForBody is a helper function which makes http calls until http server is up
// and then returns body of the successful call.
func waitForBody(urlToGet string) (body []byte, err error) {
	tries := 60

	// Get data, but we need to wait a bit for http server.
	for i := 0; i <= tries; i++ {
		// Try to get web page.
		body, err = getBody(urlToGet)
		if err == nil {
			return body, err
		}

		// If there is a syscall.ECONNREFUSED error (web server not available) then retry.
		if urlError, ok := err.(*url.Error); ok {
			if opError, ok := urlError.Err.(*net.OpError); ok {
				if osSyscallError, ok := opError.Err.(*os.SyscallError); ok {
					if osSyscallError.Err == syscall.ECONNREFUSED {
						time.Sleep(1 * time.Second)
						continue
					}
				}
			}
		}

		// There was an error, and it wasn't syscall.ECONNREFUSED.
		return nil, err
	}

	return nil, fmt.Errorf("failed to GET %s after %d tries: %s", urlToGet, tries, err)
}

// getBody is a helper function which retrieves http body from given address.
func getBody(urlToGet string) ([]byte, error) {
	resp, err := http.Get(urlToGet) // nolint
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
