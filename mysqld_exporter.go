package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-sql-driver/mysql"
	"github.com/go-sql-driver/mysql"
	"github.com/percona/exporter_shared"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/ini.v1"
	"gopkg.in/yaml.v2"

	"github.com/percona/mysqld_exporter/collector"
)

// System variable params formatting.
// See: https://github.com/go-sql-driver/mysql#system-variables
const (
	sessionSettingsParam = `log_slow_filter=%27tmp_table_on_disk,filesort_on_disk%27`
	timeoutParam         = `lock_wait_timeout=%d`
)

var (
	webConfig     = webflag.AddFlags(kingpin.CommandLine)
	showVersion = kingpin.Flag(
		"version",
		"Print version information.",
	).Default("false").Bool()
	listenAddress = kingpin.Flag(
		"web.listen-address",
		"Address to listen on for web interface and telemetry.",
	).Default(":9104").String()
	metricPath = kingpin.Flag(
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
	tlsInsecureSkipVerify = kingpin.Flag(
		"tls.insecure-skip-verify",
		"Ignore certificate and server verification when using a tls connection.",
	).Bool()

	exporterLockTimeout = kingpin.Flag(
		"exporter.lock_wait_timeout",
		"Set a lock_wait_timeout on the connection to avoid long metadata locking.",
	).Default("2").Int()
	exporterLogSlowFilter = kingpin.Flag(
		"exporter.log_slow_filter",
		"Add a log_slow_filter to avoid slow query logging of scrapes. NOTE: Not supported by Oracle MySQL.",
	).Default("false").Bool()
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

	dsn string
)

type webAuth struct {
	User     string `yaml:"server_user,omitempty"`
	Password string `yaml:"server_password,omitempty"`
}

type basicAuthHandler struct {
	handler  http.HandlerFunc
	user     string
	password string
}

func (h *basicAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, password, ok := r.BasicAuth()
	if !ok || password != h.password || user != h.user {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"metrics\"")
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	h.handler(w, r)
}

// scrapers lists all possible collection methods and if they should be enabled by default.
var scrapers = map[collector.Scraper]bool{
	collector.ScrapeGlobalStatus{}:                        false,
	collector.ScrapeGlobalVariables{}:                     false,
	collector.ScrapeSlaveStatus{}:                         false,
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
	collector.ScrapeUserStat{}:                            false,
	collector.ScrapeClientStat{}:                          false,
	collector.ScrapeTableStat{}:                           false,
	collector.ScrapeSchemaStat{}:                          false,
	collector.ScrapeInnodbCmp{}:                           false,
	collector.ScrapeInnodbCmpMem{}:                        false,
	collector.ScrapeQueryResponseTime{}:                   false,
	collector.ScrapeEngineTokudbStatus{}:                  false,
	collector.ScrapeEngineInnodbStatus{}:                  false,
	collector.ScrapeHeartbeat{}:                           false,
	collector.ScrapeSlaveHosts{}:                          false,
	collector.ScrapeReplicaHost{}:                         false,
}

func parseMycnf(config interface{}) (string, error) {
	var dsn string
	opts := ini.LoadOptions{
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
		dsn = fmt.Sprintf("%s?tls=custom", dsn)
	}

	log.Debugln(dsn)
	return dsn, nil
}

func customizeTLS(sslCA string, sslCert string, sslKey string) error {
	var tlsCfg tls.Config
	caBundle := x509.NewCertPool()
	pemCA, err := ioutil.ReadFile(sslCA)
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
		tlsCfg.InsecureSkipVerify = *tlsInsecureSkipVerify
	}
	mysql.RegisterTLSConfig("custom", &tlsCfg)
	return nil
}

func init() {
	prometheus.MustRegister(version.NewCollector("mysqld_exporter"))
}

func newHandler(metrics collector.Metrics, scrapers []collector.Scraper, logger log.Logger) http.HandlerFunc {
	var processing_lr, processing_mr, processing_hr uint32 = 0, 0, 0 // default value is already 0, but for extra clarity
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() { log.Debugf("Request elapsed time: %v %s", time.Since(start), query_collect) }()

		query_collect := r.URL.Query().Get("collect[]")
		filteredScrapers := scrapers
		params := r.URL.Query()["collect[]"]
		switch query_collect {
		case "custom_query.hr":
			if !atomic.CompareAndSwapUint32(&processing_hr, 0, 1) {
				log.Warnf("Received metrics HR request while previous still in progress: returning 429 Too Many Requests")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			defer atomic.StoreUint32(&processing_hr, 0)
		case "custom_query.mr":
			if !atomic.CompareAndSwapUint32(&processing_mr, 0, 1) {
				log.Warnf("Received metrics MR request while previous still in progress: returning 429 Too Many Requests")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			defer atomic.StoreUint32(&processing_mr, 0)
		case "custom_query.lr":
			if !atomic.CompareAndSwapUint32(&processing_lr, 0, 1) {
				log.Warnf("Received metrics LR request while previous still in progress: returning 429 Too Many Requests")
				http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
				return
			}
			defer atomic.StoreUint32(&processing_lr, 0)
		}

		filteredScrapers := scrapers
		params := r.URL.Query()["collect[]"]
		// Use request context for cancellation when connection gets closed.
		ctx := r.Context()
		// If a timeout is configured via the Prometheus header, add it to the context.
		if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
			timeoutSeconds, err := strconv.ParseFloat(v, 64)
			if err != nil {
				level.Error(logger).Log("msg", "Failed to parse timeout from Prometheus header", "err", err)
			} else {
				if *timeoutOffset >= timeoutSeconds {
					// Ignore timeout offset if it doesn't leave time to scrape.
					level.Error(logger).Log("msg", "Timeout offset should be lower than prometheus scrape timeout", "offset", *timeoutOffset, "prometheus_scrape_timeout", timeoutSeconds)
				} else {
					// Subtract timeout offset from timeout.
					timeoutSeconds -= *timeoutOffset
				}
				// Create new timeout context with request context as parent.
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds*float64(time.Second)))
				defer cancel()
				// Overwrite request with timeout context.
				r = r.WithContext(ctx)
			}
		}
		level.Debug(logger).Log("msg", "collect[] params", "params", strings.Join(params, ","))

		// Check if we have some "collect[]" query parameters.
		if len(params) > 0 {
			filters := make(map[string]bool)
			for _, param := range params {
				filters[param] = true
			}

			filteredScrapers = nil
			for _, scraper := range scrapers {
				if filters[scraper.Name()] {
					filteredScrapers = append(filteredScrapers, scraper)
				}
			}
		}

		// Copy db as local variable, so the pointer passed to newHandler doesn't get updated.
		db := db
		// If there is no global connection pool then create new.
		var err error
		if db == nil {
			db, err = newDB(dsn)
			if err != nil {
				log.Fatalln("Error opening connection to database:", err)
				return
			}
			defer db.Close()
		}

		registry := prometheus.NewRegistry()
		registry.MustRegister(collector.New(ctx, dsn, metrics, filteredScrapers, logger))

		gatherers := prometheus.Gatherers{}
		if defaultGatherer {
			gatherers = append(gatherers, prometheus.DefaultGatherer)
		}
		gatherers = append(gatherers, registry)

		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, promhttp.HandlerOpts{
			// mysqld_exporter has multiple collectors, if one fails,
			// we still should report metrics from collectors that succeeded.
			ErrorHandling: promhttp.ContinueOnError,
			ErrorLog:      log.NewErrorLogger(),
		})
		if cfg.User != "" && cfg.Password != "" {
			h = &basicAuthHandler{handler: h.ServeHTTP, user: cfg.User, password: cfg.Password}
		}
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
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("mysqld_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Print("mysqld_exporter"))
		os.Exit(0)
	}

	// landingPage contains the HTML served at '/'.
	// TODO: Make this nicer and more informative.
	landingPage := []byte(`<html>
<head><title>MySQLd exporter</title></head>
<body>
<h1>MySQL 3-in-1 exporter</h1>
<ul>
	<li><a href="` + *metricPath + `-hr">high-res metrics</a></li>
	<li><a href="` + *metricPath + `-mr">medium-res metrics</a></li>
	<li><a href="` + *metricPath + `-lr">low-res metrics</a></li>
</ul>
<h1>MySQL exporter</h1>
<ul>
	<li><a href="` + *metricPath + `">all metrics</a></li>
</ul>
</body>
</html>
`)

	level.Info(logger).Log("msg", "Starting mysqld_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", version.BuildContext())

	dsn = os.Getenv("DATA_SOURCE_NAME")
	if len(dsn) == 0 {
		var err error
		if dsn, err = parseMycnf(*configMycnf); err != nil {
			level.Info(logger).Log("msg", "Error parsing my.cnf", "file", *configMycnf, "err", err)

			//TODO:X1: or return?? [diff]
			os.Exit(1)
		}
	}

	// Setup extra params for the DSN, default to having a lock timeout.
	dsnParams := []string{fmt.Sprintf(timeoutParam, *exporterLockTimeout)}
	if *exporterLogSlowFilter {
		dsnParams = append(dsnParams, sessionSettingsParam)
	}

	// The parseMycnf function will set the TLS config in case certificates are being defined in
	// the config file. If the user also specified command line parameters, these parameters should
	// override the ones from the cnf file.
	if *mysqlSSLCAFile != "" || (*mysqlSSLCertFile != "" && *mysqlSSLKeyFile != "") {
		if err := customizeTLS(*mysqlSSLCAFile, *mysqlSSLCertFile, *mysqlSSLKeyFile); err != nil {
			log.Fatalf("failed to register a custom TLS configuration for mysql dsn: %s", err)
		}
		var err error
		dsn, err = setTLSConfig(dsn)
		if err != nil {
			log.Fatalf("failed to register a custom TLS configuration for mysql dsn: %s", err)
		}
	}

	// This could be improved using the driver's DSN parse and config format functions but this is
	// how upstream does it.
	if strings.Contains(dsn, "?") {
		dsn += "&"
	} else {
		dsn += "?"
	}
	dsn += strings.Join(dsnParams, "&")

	// Open global connection pool if requested.
	var db *sql.DB

	var err error

	if *exporterGlobalConnPool {
		db, err = newDB(dsn)
		if err != nil {
			log.Fatalln("Error opening connection to database:", err)
			return
		}
		defer db.Close()
	}

	cfg := &webAuth{}
	httpAuth := os.Getenv("HTTP_AUTH")

	// Those flags defined in "github.com/percona/exporter_shared"
	webAuthFile := kingpin.CommandLine.GetFlag("web.auth-file").Default("").String()
	sslCertFile := kingpin.CommandLine.GetFlag("web.ssl-cert-file").Default("").String()
	sslKeyFile := kingpin.CommandLine.GetFlag("web.ssl-key-file").Default("").String()

	if *webAuthFile != "" {
		bytes, err := ioutil.ReadFile(*webAuthFile)
		if err != nil {
			log.Fatal("Cannot read auth file: ", err)
			return
		}
		if err := yaml.Unmarshal(bytes, cfg); err != nil {
			log.Fatal("Cannot parse auth file: ", err)
			return
		}
	} else if httpAuth != "" {
		data := strings.SplitN(httpAuth, ":", 2)
		if len(data) != 2 || data[0] == "" || data[1] == "" {
			log.Fatal("HTTP_AUTH should be formatted as user:password")
			return
		}
		cfg.User = data[0]
		cfg.Password = data[1]
	}
	if cfg.User != "" && cfg.Password != "" {
		log.Infoln("HTTP basic authentication is enabled")
	}

	if *sslCertFile != "" && *sslKeyFile == "" || *sslCertFile == "" && *sslKeyFile != "" {
		log.Fatal("One of the flags -web.ssl-cert or -web.ssl-key is missed to enable HTTPS/TLS")
		return
	}
	ssl := false
	if *sslCertFile != "" && *sslKeyFile != "" {
		if _, err := os.Stat(*sslCertFile); os.IsNotExist(err) {
			log.Fatal("SSL certificate file does not exist: ", *sslCertFile)
			return
		}
		if _, err := os.Stat(*sslKeyFile); os.IsNotExist(err) {
			log.Fatal("SSL key file does not exist: ", *sslKeyFile)
			return
		}
		ssl = true
		log.Infoln("HTTPS/TLS is enabled")
	}

	// Register only scrapers enabled by flag.
	enabledScrapers := []collector.Scraper{}
	for scraper, enabled := range scraperFlags {
		if *enabled {
			level.Info(logger).Log("msg", "Scraper enabled", "scraper", scraper.Name())
			enabledScrapers = append(enabledScrapers, scraper)
		}
	}
	handlerFunc := newHandler(collector.NewMetrics(), enabledScrapers, logger)
	http.Handle(*metricPath, promhttp.InstrumentMetricHandler(prometheus.DefaultRegisterer, handlerFunc))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(landingPage)
	})

	level.Info(logger).Log("msg", "Listening on address", "address", *listenAddress)
	srv := &http.Server{Addr: *listenAddress}
	if err := web.ListenAndServe(srv, *webConfig, logger); err != nil {
		level.Error(logger).Log("msg", "Error starting HTTP server", "err", err)
		os.Exit(1)
	}

	// Use default mux for /debug/vars and /debug/pprof
	mux := http.DefaultServeMux

	// Defines what to scrape in each resolution.
	all, hr, mr, lr := enabledScrapers(scraperFlags)

	// TODO: Remove later. It's here for backward compatibility. See: https://jira.percona.com/browse/PMM-2180.
	mux.Handle(*metricPath+"-hr", newHandler(cfg, db, collector.NewMetrics("hr"), hr, true))
	mux.Handle(*metricPath+"-mr", newHandler(cfg, db, collector.NewMetrics("mr"), mr, false))
	mux.Handle(*metricPath+"-lr", newHandler(cfg, db, collector.NewMetrics("lr"), lr, false))

	// Handle all metrics on one endpoint.
	mux.Handle(*metricPath, newHandler(cfg, db, collector.NewMetrics(""), all, false))

	// Log which scrapers are enabled.
	if len(hr) > 0 {
		log.Infof("Enabled High Resolution scrapers:")
		for _, scraper := range hr {
			log.Infof(" --collect.%s", scraper.Name())
		}
	}
	if len(mr) > 0 {
		log.Infof("Enabled Medium Resolution scrapers:")
		for _, scraper := range mr {
			log.Infof(" --collect.%s", scraper.Name())
		}
	}
	if len(lr) > 0 {
		log.Infof("Enabled Low Resolution scrapers:")
		for _, scraper := range lr {
			log.Infof(" --collect.%s", scraper.Name())
		}
	}
	if len(all) > 0 {
		log.Infof("Enabled Resolution Independent scrapers:")
		for _, scraper := range all {
			log.Infof(" --collect.%s", scraper.Name())
		}
	}

	srv := &http.Server{
		Addr:    *listenAddress,
		Handler: mux,
	}

	log.Infoln("Listening on", *listenAddress)
	if ssl {
		// https
		mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
			w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			w.Write(landingPage)
		})
		srv.TLSConfig = exporter_shared.TLSConfig()
		srv.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0)

		log.Fatal(srv.ListenAndServeTLS(*sslCertFile, *sslKeyFile))
	} else {
		// http
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write(landingPage)
		})

		log.Fatal(srv.ListenAndServe())
	}

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