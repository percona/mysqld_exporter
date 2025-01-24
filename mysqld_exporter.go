// Copyright 2018 The Prometheus Authors
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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-sql-driver/mysql"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/ini.v1"

	"github.com/percona/mysqld_exporter/collector"
	"github.com/percona/mysqld_exporter/config"
	pcl "github.com/percona/mysqld_exporter/percona/perconacollector"
)

var (
	// TODO: remove later. It's here for backward compatibility.
	webConfig = kingpin.Flag(
		"web.config",
		"[DEPRECATED] Path to config yaml file that can enable TLS or authentication.",
	).Default("").String()
	metricsPath = kingpin.Flag(
		"web.telemetry-path",
		"Path under which to expose metrics.",
	).Default("/metrics").String()
	timeoutOffset = kingpin.Flag(
		"timeout-offset",
		"Offset to subtract from timeout in seconds.",
	).Default("0.25").Float64()
	configMycnf = kingpin.Flag(
		"config.my-cnf",
		"Path to .my.cnf file to read MySQL credentials from.",
	).Default(path.Join(os.Getenv("HOME"), ".my.cnf")).String()

	exporterGlobalConnPool = kingpin.Flag(
		"exporter.global-conn-pool",
		"Use global connection pool instead of creating new pool for each http request.",
	).Default("true").Bool()
	exporterMaxOpenConns = kingpin.Flag(
		"exporter.max-open-conns",
		"Maximum number of open connections to the database. https://golang.org/pkg/database/sql/#DB.SetMaxOpenConns",
	).Default("3").Int()
	exporterMaxIdleConns = kingpin.Flag(
		"exporter.max-idle-conns",
		"Maximum number of connections in the idle connection pool. https://golang.org/pkg/database/sql/#DB.SetMaxIdleConns",
	).Default("3").Int()
	exporterConnMaxLifetime = kingpin.Flag(
		"exporter.conn-max-lifetime",
		"Maximum amount of time a connection may be reused. https://golang.org/pkg/database/sql/#DB.SetConnMaxLifetime",
	).Default("1m").Duration()
	collectAll = kingpin.Flag(
		"collect.all",
		"Collect all metrics.",
	).Default("false").Bool()

	mysqlSSLCAFile = kingpin.Flag(
		"mysql.ssl-ca-file",
		"SSL CA file for the MySQL connection",
	).ExistingFile()

	mysqlSSLCertFile = kingpin.Flag(
		"mysql.ssl-cert-file",
		"SSL Cert file for the MySQL connection",
	).ExistingFile()

	mysqlSSLKeyFile = kingpin.Flag(
		"mysql.ssl-key-file",
		"SSL Key file for the MySQL connection",
	).ExistingFile()

	mysqlSSLSkipVerify = kingpin.Flag(
		"mysql.ssl-skip-verify",
		"Skip cert verification when connection to MySQL",
	).Bool()

	mysqldAddress = kingpin.Flag(
		"mysqld.address",
		"Address to use for connecting to MySQL",
	).Default("localhost:3306").String()
	mysqldUser = kingpin.Flag(
		"mysqld.username",
		"Username to use for connecting to MySQL",
	).String()
	tlsInsecureSkipVerify = kingpin.Flag(
		"tls.insecure-skip-verify",
		"Ignore certificate and server verification when using a tls connection.",
	).Bool()

	// This add the following flags: `--web.listen-address`, `--web.config.file`, `--web.systemd-socket (linux-only)`
	toolkitFlags = webflag.AddFlags(kingpin.CommandLine, ":9104")
	c            = config.MySqlConfigHandler{
		Config: &config.Config{},
	}
)

type errLogger struct {
	logger *slog.Logger
}

func (el *errLogger) Println(v ...interface{}) {
	el.logger.Error(fmt.Sprint(v...))
}

var _ promhttp.Logger = &errLogger{}

// scrapers lists all possible collection methods and if they should be enabled by default.
var scrapers = map[collector.Scraper]bool{
	pcl.ScrapeGlobalStatus{}:                              false,
	collector.ScrapeGlobalStatus{}:                        false,
	collector.ScrapeGlobalVariables{}:                     false,
	collector.ScrapePlugins{}:                             false,
	collector.ScrapeSlaveStatus{}:                         false,
	pcl.ScrapeProcesslist{}:                               false,
	collector.ScrapeProcesslist{}:                         false,
	collector.ScrapeUser{}:                                false,
	collector.ScrapeTableSchema{}:                         false,
	collector.ScrapeInfoSchemaInnodbTablespaces{}:         false,
	collector.ScrapeInnodbMetrics{}:                       false,
	collector.ScrapeAutoIncrementColumns{}:                false,
	collector.ScrapeBinlogSize{}:                          false,
	collector.ScrapePerfTableIOWaits{}:                    false,
	collector.ScrapePerfIndexIOWaits{}:                    false,
	collector.ScrapePerfTableLockWaits{}:                  false,
	collector.ScrapePerfEventsStatements{}:                false,
	collector.ScrapePerfEventsStatementsSum{}:             false,
	collector.ScrapePerfEventsWaits{}:                     false,
	collector.ScrapePerfFileEvents{}:                      false,
	collector.ScrapePerfFileInstances{}:                   false,
	collector.ScrapePerfMemoryEvents{}:                    false,
	collector.ScrapePerfReplicationGroupMembers{}:         false,
	collector.ScrapePerfReplicationGroupMemberStats{}:     false,
	collector.ScrapePerfReplicationApplierStatsByWorker{}: false,
	collector.ScrapeSysUserSummary{}:                      false,
	collector.ScrapeUserStat{}:                            false,
	collector.ScrapeClientStat{}:                          false,
	collector.ScrapeTableStat{}:                           false,
	collector.ScrapeSchemaStat{}:                          false,
	collector.ScrapeInnodbCmp{}:                           false,
	collector.ScrapeInnodbCmpMem{}:                        false,
	pcl.ScrapeInnodbCmp{}:                                 false,
	pcl.ScrapeInnodbCmpMem{}:                              false,
	collector.ScrapeQueryResponseTime{}:                   false,
	collector.ScrapeEngineTokudbStatus{}:                  false,
	collector.ScrapeEngineInnodbStatus{}:                  false,
	collector.ScrapeHeartbeat{}:                           false,
	collector.ScrapeSlaveHosts{}:                          false,
	collector.ScrapeReplicaHost{}:                         false,
	pcl.ScrapeCustomQuery{Resolution: pcl.HR}:             false,
	pcl.ScrapeCustomQuery{Resolution: pcl.MR}:             false,
	pcl.ScrapeCustomQuery{Resolution: pcl.LR}:             false,
	pcl.NewStandardGo():                                   false,
	pcl.NewStandardProcess():                              false,
}

// TODO Remove
var scrapersHr = map[collector.Scraper]struct{}{
	pcl.ScrapeGlobalStatus{}:                  {},
	collector.ScrapeInnodbMetrics{}:           {},
	pcl.ScrapeCustomQuery{Resolution: pcl.HR}: {},
}

// TODO Remove
var scrapersMr = map[collector.Scraper]struct{}{
	collector.ScrapeSlaveStatus{}:             {},
	pcl.ScrapeProcesslist{}:                   {},
	collector.ScrapePerfEventsWaits{}:         {},
	collector.ScrapePerfFileEvents{}:          {},
	collector.ScrapePerfTableLockWaits{}:      {},
	collector.ScrapeQueryResponseTime{}:       {},
	collector.ScrapeEngineInnodbStatus{}:      {},
	pcl.ScrapeInnodbCmp{}:                     {},
	pcl.ScrapeInnodbCmpMem{}:                  {},
	pcl.ScrapeCustomQuery{Resolution: pcl.MR}: {},
}

// TODO Remove
var scrapersLr = map[collector.Scraper]struct{}{
	collector.ScrapeGlobalVariables{}:             {},
	collector.ScrapePlugins{}:                     {},
	collector.ScrapeTableSchema{}:                 {},
	collector.ScrapeAutoIncrementColumns{}:        {},
	collector.ScrapeBinlogSize{}:                  {},
	collector.ScrapePerfTableIOWaits{}:            {},
	collector.ScrapePerfIndexIOWaits{}:            {},
	collector.ScrapePerfFileInstances{}:           {},
	collector.ScrapeUserStat{}:                    {},
	collector.ScrapeTableStat{}:                   {},
	collector.ScrapePerfEventsStatements{}:        {},
	collector.ScrapeClientStat{}:                  {},
	collector.ScrapeInfoSchemaInnodbTablespaces{}: {},
	collector.ScrapeEngineTokudbStatus{}:          {},
	collector.ScrapeHeartbeat{}:                   {},
	pcl.ScrapeCustomQuery{Resolution: pcl.LR}:     {},
}

func parseMycnf(config interface{}, logger *slog.Logger) (string, error) {
	var dsn string
	opts := ini.LoadOptions{
		// MySQL ini file can have boolean keys.
		// PMM-2469: my.cnf can have boolean keys.
		AllowBooleanKeys: true,
	}
	cfg, err := ini.LoadSources(opts, config)
	if err != nil {
		return dsn, fmt.Errorf("failed reading ini file: %s", err)
	}
	user := cfg.Section("client").Key("user").String()
	password := cfg.Section("client").Key("password").String()
	if user == "" {
		return dsn, fmt.Errorf("no user specified under [client] in %s", config)
	}
	host := cfg.Section("client").Key("host").MustString("localhost")
	port := cfg.Section("client").Key("port").MustUint(3306)
	socket := cfg.Section("client").Key("socket").String()
	sslCA := cfg.Section("client").Key("ssl-ca").String()
	sslCert := cfg.Section("client").Key("ssl-cert").String()
	sslKey := cfg.Section("client").Key("ssl-key").String()
	passwordPart := ""
	if password != "" {
		passwordPart = ":" + password
	} else {
		if sslKey == "" {
			return dsn, fmt.Errorf("password or ssl-key should be specified under [client] in %s", config)
		}
	}
	if socket != "" {
		dsn = fmt.Sprintf("%s%s@unix(%s)/", user, passwordPart, socket)
	} else {
		dsn = fmt.Sprintf("%s%s@tcp(%s:%d)/", user, passwordPart, host, port)
	}
	if sslCA != "" {
		if tlsErr := customizeTLS(sslCA, sslCert, sslKey); tlsErr != nil {
			tlsErr = fmt.Errorf("failed to register a custom TLS configuration for mysql dsn: %s", tlsErr)
			return dsn, tlsErr
		}
		dsn, err = setTLSConfig(dsn)
		if err != nil {
			return "", fmt.Errorf("cannot set TLS configuration: %s", err)
		}
	}

	logger.Debug("", "dsn", dsn)
	return dsn, nil
}

func customizeTLS(sslCA string, sslCert string, sslKey string) error {
	var tlsCfg tls.Config
	caBundle := x509.NewCertPool()
	pemCA, err := os.ReadFile(filepath.Clean(sslCA))
	if err != nil {
		return err
	}
	if ok := caBundle.AppendCertsFromPEM(pemCA); ok {
		tlsCfg.RootCAs = caBundle
	} else {
		return fmt.Errorf("failed parse pem-encoded CA certificates from %s", sslCA)
	}
	if sslCert != "" && sslKey != "" {
		certPairs := make([]tls.Certificate, 0, 1)
		keypair, err := tls.LoadX509KeyPair(sslCert, sslKey)
		if err != nil {
			return fmt.Errorf("failed to parse pem-encoded SSL cert %s or SSL key %s: %s",
				sslCert, sslKey, err)
		}
		certPairs = append(certPairs, keypair)
		tlsCfg.Certificates = certPairs
	} else {
		return fmt.Errorf("missing certificates. Cannot specify only SSL CA file")
	}

	tlsCfg.InsecureSkipVerify = *mysqlSSLSkipVerify || *tlsInsecureSkipVerify
	return mysql.RegisterTLSConfig("custom", &tlsCfg)
}

func filterScrapers(scrapers []collector.Scraper, collectParams []string) []collector.Scraper {
	var filteredScrapers []collector.Scraper

	// Check if we have some "collect[]" query parameters.
	if len(collectParams) > 0 {
		filters := make(map[string]bool)
		for _, param := range collectParams {
			filters[param] = true
		}

		for _, scraper := range scrapers {
			if filters[scraper.Name()] {
				filteredScrapers = append(filteredScrapers, scraper)
			}
		}
	}
	if len(filteredScrapers) == 0 {
		return scrapers
	}
	return filteredScrapers
}

func getScrapeTimeoutSeconds(r *http.Request, offset float64) (float64, error) {
	var timeoutSeconds float64
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		var err error
		timeoutSeconds, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse timeout from Prometheus header: %v", err)
		}
	}
	if timeoutSeconds == 0 {
		return 0, nil
	}
	if timeoutSeconds < 0 {
		return 0, fmt.Errorf("timeout value from Prometheus header is invalid: %f", timeoutSeconds)
	}

	if offset >= timeoutSeconds {
		// Ignore timeout offset if it doesn't leave time to scrape.
		return 0, fmt.Errorf("timeout offset (%f) should be lower than prometheus scrape timeout (%f)", offset, timeoutSeconds)
	} else {
		// Subtract timeout offset from timeout.
		timeoutSeconds -= offset
	}
	return timeoutSeconds, nil
}

func setTLSConfig(dsn string) (string, error) {
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	cfg.TLSConfig = "custom"

	return cfg.FormatDSN(), nil
}

func init() {
	prometheus.MustRegister(versioncollector.NewCollector("mysqld_exporter"))
}

func newHandler(metrics collector.Metrics, scrapers []collector.Scraper, defaultGatherer bool, logger *slog.Logger) http.HandlerFunc {
	var processing_lr, processing_mr, processing_hr uint32 = 0, 0, 0 // default value is already 0, but for extra clarity
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		q := r.URL.Query()
		query_collect := q.Get("collect[]")

		switch query_collect {
		case "custom_query.hr":
			if !atomic.CompareAndSwapUint32(&processing_hr, 0, 1) {
				logger.Warn("Received metrics HR request while previous still in progress: returning 429 Too Many Requests")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			defer atomic.StoreUint32(&processing_hr, 0)
		case "custom_query.mr":
			if !atomic.CompareAndSwapUint32(&processing_mr, 0, 1) {
				logger.Warn("Received metrics MR request while previous still in progress: returning 429 Too Many Requests")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			defer atomic.StoreUint32(&processing_mr, 0)
		case "custom_query.lr":
			if !atomic.CompareAndSwapUint32(&processing_lr, 0, 1) {
				logger.Warn("Received metrics LR request while previous still in progress: returning 429 Too Many Requests")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			defer atomic.StoreUint32(&processing_lr, 0)
		}
		defer func() {
			logger.Debug("Request elapsed time", "sinceStart", time.Since(start), "query_collect", query_collect)
		}()

		// Use request context for cancellation when connection gets closed.
		ctx := r.Context()
		// If a timeout is configured via the Prometheus header, add it to the context.
		timeoutSeconds, err := getScrapeTimeoutSeconds(r, *timeoutOffset)
		if err != nil {
			logger.Error("Error getting timeout from Prometheus header", "err", err)
		}
		if timeoutSeconds > 0 {
			// Create new timeout context with request context as parent.
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds*float64(time.Second)))
			defer cancel()
			// Overwrite request with timeout context.
			r = r.WithContext(ctx)
		}

		collect := q["collect[]"]
		logger.Debug("msg", "collect[] params", strings.Join(collect, ","))

		filteredScrapers := filterScrapers(scrapers, collect)

		var dsn string
		target := ""
		if q.Has("target") {
			target = q.Get("target")
		}

		cfg := c.GetConfig()
		cfgsection, ok := cfg.Sections["client"]
		if !ok {
			logger.Error("Failed to parse section [client] from config file", "err", err)
		}
		if dsn, err = cfgsection.FormDSN(target); err != nil {
			logger.Error("Failed to form dsn from section [client]", "err", err)
		}

		registry := prometheus.NewRegistry()
		registry.MustRegister(collector.New(ctx, dsn, metrics, filteredScrapers, logger))

		gatherers := prometheus.Gatherers{}
		if defaultGatherer {
			gatherers = append(gatherers, prometheus.DefaultGatherer)
		}
		gatherers = append(gatherers, registry)

		eLogger := &errLogger{logger: logger}
		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{
			// mysqld_exporter has multiple collectors; if one fails,
			// we still should handle metrics from collectors that succeeded.
			ErrorHandling: promhttp.ContinueOnError,
			ErrorLog:      eLogger,
		})
		h.ServeHTTP(w, r)
	}
}

func main() {
	// Generate ON/OFF flags for all scrapers.
	scraperFlags := map[collector.Scraper]*bool{}
	for scraper, enabledByDefault := range scrapers {
		defaultOn := "false"
		if enabledByDefault {
			defaultOn = "true"
		}

		f := kingpin.Flag(
			"collect."+scraper.Name(),
			scraper.Help(),
		).Default(defaultOn).Bool()

		scraperFlags[scraper] = f
	}

	// Parse flags.
	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.Version(version.Print("mysqld_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promslog.New(promslogConfig)

	// landingPage contains the ExtraHTML element part of the index page to be rendered at '/'.
	var landingPage = []byte(`
<h2>MySQL metrics in different resolutions</h2>
<ul>
	<li><a href="` + *metricsPath + `-hr">high-res metrics</a></li>
	<li><a href="` + *metricsPath + `-mr">medium-res metrics</a></li>
	<li><a href="` + *metricsPath + `-lr">low-res metrics</a></li>
</ul>
`)

	logger.Info("Starting mysqld_exporter", "version", version.Info())
	logger.Info("Build context", "build_context", version.BuildContext())

	dsn := os.Getenv("DATA_SOURCE_NAME")
	if len(dsn) == 0 {
		var err error
		if dsn, err = parseMycnf(*configMycnf, logger); err != nil {
			logger.Error("Error parsing my.cnf", "file", *configMycnf, "err", err)
			os.Exit(1)
		}
	}

	// The parseMycnf function will set the TLS config in case certificates are being defined in
	// the config file. If the user also specified command line parameters, these parameters should
	// override the ones from the cnf file.
	if *mysqlSSLCAFile != "" || (*mysqlSSLCertFile != "" && *mysqlSSLKeyFile != "") {
		if err := customizeTLS(*mysqlSSLCAFile, *mysqlSSLCertFile, *mysqlSSLKeyFile); err != nil {
			logger.Error("failed to register a custom TLS configuration for mysql dsn", "error", err)
		}
		var err error
		dsn, err = setTLSConfig(dsn)
		if err != nil {
			logger.Error("failed to register a custom TLS configuration for mysql dsn", "error", err)
			os.Exit(1)
		}
	}

	// Open global connection pool if requested.
	var db *sql.DB

	var err error

	if *exporterGlobalConnPool {
		db, err = newDB(dsn)
		if err != nil {
			logger.Error("Error opening connection to database", "error", err)
			return
		}
		defer db.Close()
	}

	// Use default mux for /debug/vars and /debug/pprof
	mux := http.DefaultServeMux

	// Defines what to scrape in each resolution.
	all, hr, mr, lr := enabledScrapers(scraperFlags)

	// TODO: Remove later. It's here for backward compatibility. See: https://jira.percona.com/browse/PMM-2180.
	mux.Handle(*metricsPath+"-hr", newHandler(collector.NewMetrics("hr"), hr, true, logger))
	mux.Handle(*metricsPath+"-mr", newHandler(collector.NewMetrics("mr"), mr, false, logger))
	mux.Handle(*metricsPath+"-lr", newHandler(collector.NewMetrics("lr"), lr, false, logger))

	// Handle all metrics on one endpoint.
	mux.Handle(*metricsPath, newHandler(collector.NewMetrics(""), all, false, logger))

	// Log which scrapers are enabled.
	if len(hr) > 0 {
		logger.Info("Enabled High Resolution scrapers:")
		for _, scraper := range hr {
			var v = fmt.Sprintf(" --collect.%s", scraper.Name())
			logger.Info(v)
		}
	}
	if len(mr) > 0 {
		logger.Info("Enabled Medium Resolution scrapers:")
		for _, scraper := range mr {
			var v = fmt.Sprintf(" --collect.%s", scraper.Name())
			logger.Info(v)
		}
	}
	if len(lr) > 0 {
		logger.Info("Enabled Low Resolution scrapers:")
		for _, scraper := range lr {
			var v = fmt.Sprintf(" --collect.%s", scraper.Name())
			logger.Info(v)
		}
	}
	if len(all) > 0 {
		logger.Info("Enabled Resolution Independent scrapers:")
		for _, scraper := range all {
			var v = fmt.Sprintf(" --collect.%s", scraper.Name())
			logger.Info(v)
		}
	}

	srv := &http.Server{
		Handler: mux,
	}

	// Need to check the web.config flag as well for backward compatibility.
	if *toolkitFlags.WebConfigFile != "" && *webConfig != "" {
		logger.Error("Should specify only one web-config file")
		os.Exit(1)
	}

	// If web.config.file flag is not set, use the deprecated web.config flag.
	if *toolkitFlags.WebConfigFile == "" && *webConfig != "" {
		*toolkitFlags.WebConfigFile = *webConfig
		*webConfig = ""
	}

	// logger.Info("Starting mysqld_exporter", "version", version.Info())
	// logger.Info("Build context", "build_context", version.BuildContext())

	if err = c.ReloadConfig(*configMycnf, *mysqldAddress, *mysqldUser, *tlsInsecureSkipVerify, logger); err != nil {
		logger.Info("Error parsing host config", "file", *configMycnf, "err", err)
		os.Exit(1)
	}

	// Register only scrapers enabled by flag.
	// enabledScrapers := []collector.Scraper{}
	// for scraper, enabled := range scraperFlags {
	// 	if *enabled {
	// 		logger.Info("Scraper enabled", "scraper", scraper.Name())
	// 		enabledScrapers = append(enabledScrapers, scraper)
	// 	}
	// }
	// handlerFunc := newHandler(collector.NewMetrics(""), enabledScrapers, false, logger)
	// http.Handle(*metricsPath, promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, handlerFunc))

	if *metricsPath != "/" && *metricsPath != "" {
		landingConfig := web.LandingConfig{
			Name:        "MySQLd Exporter",
			Description: "Prometheus Exporter for MySQL servers",
			Version:     version.Info(),
			Links: []web.LandingLinks{
				{
					Address: *metricsPath,
					Text:    "Metrics",
				},
			},
			ExtraHTML: string(landingPage),
		}
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			logger.Error("Error creating landing page", "err", err)
			os.Exit(1)
		}
		mux.Handle("/", landingPage)
	}

	// mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
	// 	w.Write(landingPage)
	// })
	mux.HandleFunc("/probe", handleProbe(all, logger))
	mux.HandleFunc("/-/reload", func(w http.ResponseWriter, r *http.Request) {
		if err = c.ReloadConfig(*configMycnf, *mysqldAddress, *mysqldUser, *tlsInsecureSkipVerify, logger); err != nil {
			logger.Warn("Error reloading host config", "file", *configMycnf, "error", err)
			return
		}
		_, _ = w.Write([]byte(`ok`))
	})

	if err := web.ListenAndServe(srv, toolkitFlags, logger); err != nil {
		logger.Error("Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}

func enabledScrapers(scraperFlags map[collector.Scraper]*bool) (all, hr, mr, lr []collector.Scraper) {
	for scraper, enabled := range scraperFlags {
		if *collectAll || *enabled {
			if _, ok := scrapers[scraper]; ok {
				all = append(all, scraper)
			}
			if _, ok := scrapersHr[scraper]; ok {
				hr = append(hr, scraper)
			}
			if _, ok := scrapersMr[scraper]; ok {
				mr = append(mr, scraper)
			}
			if _, ok := scrapersLr[scraper]; ok {
				lr = append(lr, scraper)
			}
		}
	}

	return all, hr, mr, lr
}

func newDB(dsn string) (*sql.DB, error) {
	// Validate DSN, and open connection pool.
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(*exporterMaxOpenConns)
	db.SetMaxIdleConns(*exporterMaxIdleConns)
	db.SetConnMaxLifetime(*exporterConnMaxLifetime)

	return db, nil
}
