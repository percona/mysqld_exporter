// Copyright 2024 The Prometheus Authors
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

package collector

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blang/semver/v4"

	"github.com/percona/mysqld_exporter/auth"
)

const (
	FlavorMySQL            = "mysql"
	FlavorMariaDB          = "mariadb"
	versionQuery           = "SELECT @@version;"
	performanceSchemaQuery = "SELECT @@performance_schema;"
)

type instance struct {
	db                         *sql.DB
	flavor                     string
	version                    semver.Version
	versionMajorMinor          float64
	isPerformanceSchemaEnabled bool
}

func (i *instance) loadMetadata(ctx context.Context) error {
	version, versionString, err := queryVersion(ctx, i.db)
	if err != nil {
		return err
	}
	i.version = version

	versionMajorMinor, err := strconv.ParseFloat(fmt.Sprintf("%d.%d", i.version.Major, i.version.Minor), 64)
	if err != nil {
		return err
	}
	i.versionMajorMinor = versionMajorMinor

	if strings.Contains(strings.ToLower(versionString), "mariadb") {
		i.flavor = FlavorMariaDB
	} else {
		i.flavor = FlavorMySQL
	}

	isPerformanceSchemaEnabled, err := queryPerformanceSchemaEnabled(ctx, i.db)
	if err != nil {
		return err
	}
	i.isPerformanceSchemaEnabled = isPerformanceSchemaEnabled

	return nil
}

func newInstance(ctx context.Context, dsn string, maxOpenConns, maxIdleConns int, connMaxLifetime time.Duration, provider auth.Provider) (*instance, error) {
	connector, err := auth.OpenConnector(dsn, provider)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	return newInstanceFromDB(ctx, db)
}

func newInstanceFromDB(ctx context.Context, db *sql.DB) (*instance, error) {
	i := &instance{db: db}

	if err := i.loadMetadata(ctx); err != nil {
		i.db.Close()
		return nil, err
	}

	return i, nil
}

// queryPerformanceSchemaEnabled reports whether performance_schema is enabled in the server
func queryPerformanceSchemaEnabled(ctx context.Context, db *sql.DB) (bool, error) {
	var enabled uint8
	err := db.QueryRowContext(ctx, performanceSchemaQuery).Scan(&enabled)
	if err != nil {
		return false, fmt.Errorf("failed to query performance_schema status: %w", err)
	}
	return enabled == 1, nil
}

// getDB returns the database connection for the instance.
func (i *instance) getDB() *sql.DB {
	return i.db
}

// Close closes the database connection.
func (i *instance) Close() error {
	return i.db.Close()
}

// Ping checks connection availability and possibly invalidates the connection if it fails.
func (i *instance) Ping(ctx context.Context) error {
	if err := i.db.PingContext(ctx); err != nil {
		if cerr := i.Close(); cerr != nil {
			return err
		}
		return err
	}
	return nil
}

// The result of SELECT version() is something like:
// for MariaDB: "10.5.17-MariaDB-1:10.5.17+maria~ubu2004-log"
// for MySQL: "8.0.36-28.1"
var versionRegex = regexp.MustCompile(`^((\d+)(\.\d+)(\.\d+))`)

func queryVersion(ctx context.Context, db *sql.DB) (semver.Version, string, error) {
	var version string
	err := db.QueryRowContext(ctx, versionQuery).Scan(&version)
	if err != nil {
		return semver.Version{}, version, err
	}

	matches := versionRegex.FindStringSubmatch(version)
	if len(matches) > 1 {
		parsedVersion, err := semver.ParseTolerant(matches[1])
		if err != nil {
			return semver.Version{}, version, fmt.Errorf("could not parse version from %q", matches[1])
		}
		return parsedVersion, version, nil
	}

	return semver.Version{}, version, fmt.Errorf("could not parse version from %q", version)
}
