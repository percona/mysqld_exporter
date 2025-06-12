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
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/smartystreets/goconvey/convey"
)

const dsn = "root@tcp(localhost:3306)/mysql"

func TestExporter(t *testing.T) {
	if testing.Short() {
		t.Skip("-short is passed, skipping test")
	}

	exporter := New(
		context.Background(),
		dsn,
		[]Scraper{
			ScrapeGlobalStatus{},
		},
		promslog.NewNopLogger(),
	)

	convey.Convey("Metrics describing", t, func() {
		ch := make(chan *prometheus.Desc)
		go func() {
			exporter.Describe(ch)
			close(ch)
		}()

		for range ch {
		}
	})

	convey.Convey("Metrics collection", t, func() {
		ch := make(chan prometheus.Metric)
		go func() {
			exporter.Collect(ch)
			close(ch)
		}()

		for m := range ch {
			got := readMetric(m)
			if got.labels[model.MetricNameLabel] == "mysql_up" {
				convey.So(got.value, convey.ShouldEqual, 1)
			}
		}
	})
}

func TestExporterDSN(t *testing.T) {
	convey.Convey("DSN with special characters in password (w/o table)", t, func() {
		dsn := "test:UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+=@tcp(localhost:3306)/"
		exporter := New(
			context.Background(),
			dsn,
			[]Scraper{
				ScrapeGlobalStatus{},
			},
			promslog.NewNopLogger(),
		)
		convey.So(exporter.dsn, convey.ShouldEqual, "test:UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+=@tcp(localhost:3306)/?lock_wait_timeout=0")
	})

	convey.Convey("DSN with special characters in password (with table)", t, func() {
		dsn := "test:UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+=@tcp(localhost:3306)/mysql"
		exporter := New(
			context.Background(),
			dsn,
			[]Scraper{
				ScrapeGlobalStatus{},
			},
			promslog.NewNopLogger(),
		)
		convey.So(exporter.dsn, convey.ShouldEqual, "test:UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+=@tcp(localhost:3306)/mysql?lock_wait_timeout=0")
	})

	convey.Convey("DSN with special characters in password, with tls", t, func() {
		dsn := "test:UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+=@tcp(localhost:3306)/?tls=true"
		exporter := New(
			context.Background(),
			dsn,
			[]Scraper{
				ScrapeGlobalStatus{},
			},
			promslog.NewNopLogger(),
		)
		convey.So(exporter.dsn, convey.ShouldEqual, "test:UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+=@tcp(localhost:3306)/?tls=true&lock_wait_timeout=0")
	})

	convey.Convey("DSN with special characters in password, no tls", t, func() {
		dsn := "test:UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+=@tcp(localhost:3306)/test?tls=skip-verify"
		exporter := New(
			context.Background(),
			dsn,
			[]Scraper{
				ScrapeGlobalStatus{},
			},
			promslog.NewNopLogger(),
		)
		convey.So(exporter.dsn, convey.ShouldEqual, "test:UfY9s73Gx`~!?@#$%^&*(){}[]<>|/:;,.-_+=@tcp(localhost:3306)/test?tls=skip-verify&lock_wait_timeout=0")
	})
}

func TestGetMySQLVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("-short is passed, skipping test")
	}

	convey.Convey("Version parsing", t, func() {
		instance, err := newInstance(dsn)
		convey.So(err, convey.ShouldBeNil)

		convey.So(instance.versionMajorMinor, convey.ShouldBeBetweenOrEqual, 5.7, 11.4)
	})
}
