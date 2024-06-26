#########################
### tests

# measures avg scrape time and compares old vs new exporters
test-performance:
	go test -v -run '^TestPerformance$$' -args -doRun=true

extraMetrics = false
multipleLabels = false
dumpMetrics = false

test-metrics:
	go test -v -run '^TestMissingMetrics$$' -args -doRun=true

test-labels:
	go test -v -run '^TestMissingLabels$$' -args -doRun=true

test-resolutions-duplicates:
	go test -v -run '^TestResolutionsMetricDuplicates$$' -args -doRun=true

test-resolutions:
	go test -v -run '^TestResolutions$$' -args -doRun=true

dump-metrics:
	go test -v -run '^TestDumpMetrics$$' -args -doRun=true -extraMetrics=$(extraMetrics) -multipleLabels=$(multipleLabels) -dumpMetrics=true

test-consistency: test-metrics test-resolutions test-resolutions-duplicates

#########################
### env preparation

# download exporter from provided feature build's client binary url
prepare-exporter:
	go test -v -run '^TestPrepareUpdatedExporter$\' -args -doRun=true -url=$(url)

prepare-exporter-from-repo:
	make -C ../../ build && cp ../../mysqld_exporter assets/mysqld_exporter

prepare-base-exporter:
	tar -xf assets/mysqld_exporter_percona.tar.xz -C assets/

start-mysql-db:
	docker-compose -f assets/mysql-compose.yml up -d --force-recreate --renew-anon-volumes --remove-orphans

stop-mysql-db:
	docker-compose -f assets/mysql-compose.yml down

prepare-env-from-repo: prepare-exporter-from-repo prepare-base-exporter start-mysql-db
