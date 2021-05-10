// Scrape `information_schema.innodb_sys_tablespaces`.

package collector

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	innodbTablespacesQueryv57 = `
	SELECT
	    SPACE,
	    NAME,
	    ifnull(FILE_FORMAT, 'NONE') as FILE_FORMAT,
	    ifnull(ROW_FORMAT, 'NONE') as ROW_FORMAT,
	    ifnull(SPACE_TYPE, 'NONE') as SPACE_TYPE,
	    FILE_SIZE,
	    ALLOCATED_SIZE
	  FROM information_schema.innodb_sys_tablespaces
	`
	innodbTablespacesQueryv80 = `
	SELECT
	    SPACE,
	    NAME,
	    'NONE' as FILE_FORMAT,
	    ifnull(ROW_FORMAT, 'NONE') as ROW_FORMAT,
	    ifnull(SPACE_TYPE, 'NONE') as SPACE_TYPE,
	    FILE_SIZE,
	    ALLOCATED_SIZE
	  FROM information_schema.innodb_tablespaces
	`
)

var (
	infoSchemaInnodbTablesspaceInfoDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, informationSchema, "innodb_tablespace_space_info"),
		"The Tablespace information and Space ID.",
		[]string{"tablespace_name", "file_format", "row_format", "space_type"}, nil,
	)
	infoSchemaInnodbTablesspaceFileSizeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, informationSchema, "innodb_tablespace_file_size_bytes"),
		"The apparent size of the file, which represents the maximum size of the file, uncompressed.",
		[]string{"tablespace_name"}, nil,
	)
	infoSchemaInnodbTablesspaceAllocatedSizeDesc = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, informationSchema, "innodb_tablespace_allocated_size_bytes"),
		"The actual size of the file, which is the amount of space allocated on disk.",
		[]string{"tablespace_name"}, nil,
	)

	doOnce                 sync.Once
	innodbTablespacesQuery string
)

// ScrapeInfoSchemaInnodbTablespaces collects from `information_schema.innodb_sys_tablespaces`.
type ScrapeInfoSchemaInnodbTablespaces struct{}

// Name of the Scraper.
func (ScrapeInfoSchemaInnodbTablespaces) Name() string {
	return informationSchema + ".innodb_tablespaces"
}

// Help returns additional information about Scraper.
func (ScrapeInfoSchemaInnodbTablespaces) Help() string {
	return "Collect metrics from information_schema.innodb_sys_tablespaces"
}

// Version of MySQL from which scraper is available.
func (ScrapeInfoSchemaInnodbTablespaces) Version() float64 {
	return 5.7
}

// Scrape collects data.
func (ScrapeInfoSchemaInnodbTablespaces) Scrape(ctx context.Context, db *sql.DB, ch chan<- prometheus.Metric) error {
	doOnce.Do(func() {
		setInnodbTablespacesQuery(ctx, db)
	})

	tablespacesRows, err := db.QueryContext(ctx, innodbTablespacesQuery)
	if err != nil {
		return err
	}
	defer tablespacesRows.Close()

	var (
		tableSpace    uint32
		tableName     string
		fileFormat    string
		rowFormat     string
		spaceType     string
		fileSize      uint64
		allocatedSize uint64
	)

	for tablespacesRows.Next() {
		err = tablespacesRows.Scan(
			&tableSpace,
			&tableName,
			&fileFormat,
			&rowFormat,
			&spaceType,
			&fileSize,
			&allocatedSize,
		)
		if err != nil {
			return err
		}
		ch <- prometheus.MustNewConstMetric(
			infoSchemaInnodbTablesspaceInfoDesc, prometheus.GaugeValue, float64(tableSpace),
			tableName, fileFormat, rowFormat, spaceType,
		)
		ch <- prometheus.MustNewConstMetric(
			infoSchemaInnodbTablesspaceFileSizeDesc, prometheus.GaugeValue, float64(fileSize),
			tableName,
		)
		ch <- prometheus.MustNewConstMetric(
			infoSchemaInnodbTablesspaceAllocatedSizeDesc, prometheus.GaugeValue, float64(allocatedSize),
			tableName,
		)
	}

	return nil
}

func setInnodbTablespacesQuery(ctx context.Context, db *sql.DB) {
	if innodbTablespacesQuery != "" {
		return // this is to make it able to be tested
	}

	var res string
	query := "SHOW TABLES FROM information_schema LIKE 'INNODB_SYS_TABLESPACES'"

	// By default, assume MySQL 5.7+
	innodbTablespacesQuery = innodbTablespacesQueryv57

	err := db.QueryRowContext(ctx, query).Scan(&res)
	if err != nil {
		// if INNODB_SYS_TABLESPACES doesn't exists, assume it it MySQL 8+.
		// The table was renamed and the file_format field was removed
		if errors.Is(err, sql.ErrNoRows) {
			innodbTablespacesQuery = innodbTablespacesQueryv80
		}
	}
}
