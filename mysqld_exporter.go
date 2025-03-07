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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"

	"github.com/percona/mysqld_exporter/collector"
	"github.com/percona/mysqld_exporter/config"
	pcl "github.com/percona/mysqld_exporter/percona/perconacollector"
)

var (
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
	collectAll = kingpin.Flag(
		"collect.all",
		"Collect all metrics.",
	).Default("false").Bool()

	// This adds the following flags: `--web.listen-address`, `--web.config.file`, `--web.systemd-socket (linux-only)`
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

// // TODO Remove
// var scrapersHr = map[collector.Scraper]struct{}{
// 	pcl.ScrapeGlobalStatus{}:                  {},
// 	collector.ScrapeInnodbMetrics{}:           {},
// 	pcl.ScrapeCustomQuery{Resolution: pcl.HR}: {},
// }

// // TODO Remove
// var scrapersMr = map[collector.Scraper]struct{}{
// 	collector.ScrapeSlaveStatus{}:             {},
// 	pcl.ScrapeProcesslist{}:                   {},
// 	collector.ScrapePerfEventsWaits{}:         {},
// 	collector.ScrapePerfFileEvents{}:          {},
// 	collector.ScrapePerfTableLockWaits{}:      {},
// 	collector.ScrapeQueryResponseTime{}:       {},
// 	collector.ScrapeEngineInnodbStatus{}:      {},
// 	pcl.ScrapeInnodbCmp{}:                     {},
// 	pcl.ScrapeInnodbCmpMem{}:                  {},
// 	pcl.ScrapeCustomQuery{Resolution: pcl.MR}: {},
// }

// // TODO Remove
// var scrapersLr = map[collector.Scraper]struct{}{
// 	collector.ScrapeGlobalVariables{}:             {},
// 	collector.ScrapePlugins{}:                     {},
// 	collector.ScrapeTableSchema{}:                 {},
// 	collector.ScrapeAutoIncrementColumns{}:        {},
// 	collector.ScrapeBinlogSize{}:                  {},
// 	collector.ScrapePerfTableIOWaits{}:            {},
// 	collector.ScrapePerfIndexIOWaits{}:            {},
// 	collector.ScrapePerfFileInstances{}:           {},
// 	collector.ScrapeUserStat{}:                    {},
// 	collector.ScrapeTableStat{}:                   {},
// 	collector.ScrapePerfEventsStatements{}:        {},
// 	collector.ScrapeClientStat{}:                  {},
// 	collector.ScrapeInfoSchemaInnodbTablespaces{}: {},
// 	collector.ScrapeEngineTokudbStatus{}:          {},
// 	collector.ScrapeHeartbeat{}:                   {},
// 	pcl.ScrapeCustomQuery{Resolution: pcl.LR}:     {},
// }

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

func init() {
	prometheus.MustRegister(versioncollector.NewCollector("mysqld_exporter"))
}

func newHandler(scrapers []collector.Scraper, logger *slog.Logger) http.HandlerFunc {
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
		if len(collect) > 0 {
			logger.Info("msg", "collect[] params", strings.Join(collect, ","))
		}

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
		registry.MustRegister(collector.New(ctx, dsn, filteredScrapers, logger))

		gatherers := prometheus.Gatherers{
			prometheus.DefaultGatherer,
			registry,
		}

		eLogger := &errLogger{logger: logger}
		hOpts := promhttp.HandlerOpts{
			// mysqld_exporter has multiple collectors; if one fails,
			// we should still handle metrics from collectors that succeeded.
			ErrorHandling: promhttp.ContinueOnError,
		}
		// Enable detailed error logging if requested.
		if logger.Enabled(context.Background(), slog.LevelInfo) {
			hOpts.ErrorLog = eLogger
		}
		// Delegate http serving to Prometheus client library, which will call collector.Collect.
		h := promhttp.HandlerFor(gatherers, hOpts)

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

	logger.Info("Starting mysqld_exporter", "version", version.Info())
	logger.Info("Build context", "build_context", version.BuildContext())

	if err := c.ReloadConfig(*configMycnf, *mysqldAddress, *mysqldUser, *tlsInsecureSkipVerify, logger); err != nil {
		logger.Info("Error parsing host config", "file", *configMycnf, "err", err)
		os.Exit(1)
	}

	// Use default mux for /debug/vars and /debug/pprof
	mux := http.DefaultServeMux

	// Defines what to scrape in each resolution.
	all := enabledScrapers(scraperFlags, logger)

	// Handle all metrics on one endpoint.
	mux.Handle(*metricsPath, newHandler(all, logger))

	srv := &http.Server{
		Handler: mux,
	}

	// Register only scrapers enabled by flag, or all if --collect.all is set.
	// enabledScrapers := []collector.Scraper{}
	// for scraper, enabled := range scraperFlags {
	// 	if *enabled || *collectAll{
	// 		logger.Info("Scraper enabled", "scraper", scraper.Name())
	// 		enabledScrapers = append(enabledScrapers, scraper)
	// 	}
	// }
	// handlerFunc := newHandler(enabledScrapers, logger)
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
		}
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			logger.Error("Error creating landing page", "err", err)
			os.Exit(1)
		}
		mux.Handle("/", landingPage)
	}

	mux.HandleFunc("/probe", handleProbe(all, logger))
	mux.HandleFunc("/-/reload", func(w http.ResponseWriter, r *http.Request) {
		if err := c.ReloadConfig(*configMycnf, *mysqldAddress, *mysqldUser, *tlsInsecureSkipVerify, logger); err != nil {
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

func enabledScrapers(scraperFlags map[collector.Scraper]*bool, logger *slog.Logger) (all []collector.Scraper) {
	for scraper, enabled := range scraperFlags {
		if *collectAll || *enabled {
			if _, ok := scrapers[scraper]; ok {
				all = append(all, scraper)
				logger.Info("Scraper enabled", "scraper", scraper.Name())
			}
		}
	}

	return all
}
