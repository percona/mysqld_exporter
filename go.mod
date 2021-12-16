module github.com/percona/mysqld_exporter

go 1.17

require (
	github.com/percona/exporter_shared v0.7.3
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/go-kit/log v0.2.0
	github.com/go-sql-driver/mysql v1.6.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.32.1
	github.com/prometheus/exporter-toolkit v0.7.0
	github.com/satori/go.uuid v1.2.0
	github.com/smartystreets/goconvey v1.7.2
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/ini.v1 v1.63.2
	github.com/pkg/errors v0.9.1
	gopkg.in/yaml.v2 v2.4.0
)
