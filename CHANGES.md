# Breaking changes

## Environment variables

- `DATA_SOURCE_NAME` environment variable is deprecated
- `HTTP_AUTH` environment variable is deprecated

## Flags

- `mysql.ssl-skip-verify` is renamed to `tls.insecure-skip-verify`
- `exporter.max-open-conns`, `exporter.max-idle-conns` and `exporter.conn-max-lifetime` are aliases of the upstream
  `exporter.max_open_connections`, `exporter.max_idle_connections` and `exporter.conn_max_lifetime`; when none is set
  the upstream defaults apply (2, 1 and 0 instead of 3, 3 and 1m), and `exporter.max-open-conns` must be at least 1

## Deprecated flags

- `exporter.global-conn-pool` is deprecated

## Deprecated metrics

- scrapes_total
- scrape_errors_total
- last_scrape_error

## Deprecated endpoints

- `/metrics-hr` endpoint is deprecated
- `/metrics-mr` endpooint is deprecated
- `/metrics-lr` endpoint is deprecated
