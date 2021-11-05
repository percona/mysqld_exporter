package collector

import (
	"database/sql"
	"regexp"
	"strconv"
)

// regexps to extract version numbers from the `SHOW GLOBAL VARIABLES WHERE Variable_name = 'version'` output.
var (
	mysqlDBRegexp = regexp.MustCompile(`^\d+\.\d+`)
)

// GetMySQLVersion return parsed version of MySQL and vendor.
func GetMySQLVersion(db *sql.DB) (float64, error) {
	var name, ver string
	err := db.QueryRow(`SHOW /* pmm-agent:mysqlversion */ GLOBAL VARIABLES WHERE Variable_name = 'version'`).Scan(&name, &ver)
	if err != nil {
		return 0, err
	}
	var ven string
	err = db.QueryRow(`SHOW /* pmm-agent:mysqlversion */ GLOBAL VARIABLES WHERE Variable_name = 'version_comment'`).Scan(&name, &ven)
	if err != nil {
		return 0, err
	}

	version := mysqlDBRegexp.FindString(ver)

	mysqlVer, err := strconv.ParseFloat(version, 64)
	if err != nil {
		return 0, err
	}

	return mysqlVer, nil
}
