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

package collector

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/blang/semver/v4"

	"github.com/smartystreets/goconvey/convey"
)

func TestGetMySQLVersion_Percona(t *testing.T) {
	if testing.Short() {
		t.Skip("-short is passed, skipping test")
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("error opening a stub database connection: %s", err)
	}
	defer db.Close()

	convey.Convey("MySQL version extract", t, func() {
		var semVer semver.Version
		var err error
		mock.ExpectQuery(versionQuery).WillReturnRows(sqlmock.NewRows([]string{""}).AddRow(""))
		semVer, _, err = queryVersion(db)
		convey.ShouldBeError(err)
		convey.So(semVer.String(), convey.ShouldEqual, "0.0.0")

		mock.ExpectQuery(versionQuery).WillReturnRows(sqlmock.NewRows([]string{""}).AddRow("something"))
		semVer, _, err = queryVersion(db)
		convey.ShouldBeNil(err)
		convey.So(semVer.String(), convey.ShouldEqual, "0.0.0")

		mock.ExpectQuery(versionQuery).WillReturnRows(sqlmock.NewRows([]string{""}).AddRow("10.1.17-MariaDB"))
		semVer, _, err = queryVersion(db)
		convey.ShouldBeNil(err)
		convey.So(semVer.String(), convey.ShouldEqual, "10.1.17")

		mock.ExpectQuery(versionQuery).WillReturnRows(sqlmock.NewRows([]string{""}).AddRow("5.7.13-6-log"))
		semVer, _, err = queryVersion(db)
		convey.ShouldBeNil(err)
		convey.So(semVer.String(), convey.ShouldEqual, "5.7.13")

		mock.ExpectQuery(versionQuery).WillReturnRows(sqlmock.NewRows([]string{""}).AddRow("5.6.30-76.3-56-log"))
		semVer, _, err = queryVersion(db)
		convey.ShouldBeNil(err)
		convey.So(semVer.String(), convey.ShouldEqual, "5.6.30")

		mock.ExpectQuery(versionQuery).WillReturnRows(sqlmock.NewRows([]string{""}).AddRow("5.5.51-38.1"))
		semVer, _, err = queryVersion(db)
		convey.ShouldBeNil(err)
		convey.So(semVer.String(), convey.ShouldEqual, "5.5.51")
	})

	// Ensure all SQL queries were executed
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}
}
