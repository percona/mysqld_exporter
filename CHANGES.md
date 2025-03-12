# Breaking changes

## Environment variables

- `DATA_SOURCE_NAME` environment variable is deprecated
- `HTTP_AUTH` environment variable is deprecated

## Flags

- `mysql.ssl-skip-verify` is renamed to `tls.insecure-skip-verify`

## Deprecated flags

- `exporter.global-conn-pool` is deprecated, the exporter now uses a global connection pool by default

## Deprecated metrics

- scrapes_total
- scrape_errors_total
- last_scrape_error

## Deprecated endpoints

- `/metrics-hr` endpoint is deprecated
- `/metrics-mr` endpooint is deprecated
- `/metrics-lr` endpoint is deprecated
