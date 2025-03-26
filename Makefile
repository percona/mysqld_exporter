# Copyright 2015 The Prometheus Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GO           := go
FIRST_GOPATH := $(firstword $(subst :, ,$(shell $(GO) env GOPATH)))
PROMU        := bin/promu
pkgs          = $(shell $(GO) list ./...)

PREFIX              ?= $(shell pwd)
BIN_DIR             ?= $(shell pwd)
DOCKER_IMAGE_NAME   ?= mysqld-exporter
DOCKER_IMAGE_TAG    ?= $(subst /,-,$(shell git rev-parse --abbrev-ref HEAD))
TESTDIR              ?= $(shell mkdir -p test && realpath test)

default: help

all: format build test-short

init:             ## Install tools
	rm -rf bin/*
	cd tools && go generate -x -tags=tools

env-up:           ## Start MySQL and copy ssl certificates to /tmp
	@docker-compose up -d
	@sleep 5
	@docker container cp mysqld_exporter_db:/var/lib/mysql/client-cert.pem $(TESTDIR)
	@docker container cp mysqld_exporter_db:/var/lib/mysql/client-key.pem $(TESTDIR)
	@docker container cp mysqld_exporter_db:/var/lib/mysql/ca.pem $(TESTDIR)

.PHONY: test-docker-single-exporter
test-docker-single-exporter:
	@echo ">> testing docker image for single exporter"
	./test_image.sh "$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)" 9104

env-down:         ## Stop MySQL and clean up certs
	@docker-compose down -v
	@rm -rf ${TESTDIR}

style:            ## Check the code style
	@echo ">> checking code style"
	@! gofmt -d $(shell find . -name '*.go' -print) | grep '^'

test-short:       ## Run short tests
	@echo ">> running short tests"
	@$(GO) test -short -race $(pkgs)

test:             ## Run all tests
	@echo ">> running tests"
	@$(GO) test -race $(pkgs)

FILES = $(shell find . -type f -name '*.go')

format:           ## Format the code
	@echo ">> formatting code"
	@$(GO) fmt $(pkgs)
	@bin/goimports -local github.com/percona/pmm -l -w $(FILES)	

fumpt:            ## Format source code using fumpt and goimports.
	bin/gofumpt -l -w $(FILES)
	bin/goimports -local github.com/percona/pmm -l -w $(FILES)	

vet:              ## Run vet
	@echo ">> vetting code"
	@$(GO) vet $(pkgs)

build:            ## Build binaries
	@echo ">> building binaries"
	@$(PROMU) build --prefix $(PREFIX)

tarball:          ## Build release tarball
	@echo ">> building release tarball"
	@$(PROMU) tarball --prefix $(PREFIX) $(BIN_DIR)

docker:           ## Build docker image
	@echo ">> building docker image"
	@docker build -t "$(DOCKER_IMAGE_NAME):$(DOCKER_IMAGE_TAG)" .

help:             ## Display this help message.
	@echo "Please use \`make <target>\` where <target> is one of:"
	@grep '^[a-zA-Z]' $(MAKEFILE_LIST) | \
        awk -F ':.*?## ' 'NF==2 {printf "  %-26s%s\n", $$1, $$2}'

GO_BUILD_LDFLAGS = -ldflags " \
		-X github.com/prometheus/common/version.Version=$(shell cat VERSION) \
		-X github.com/prometheus/common/version.Revision=$(shell git rev-parse HEAD) \
		-X github.com/prometheus/common/version.Branch=$(shell git describe --always --contains --all) \
		-X github.com/prometheus/common/version.BuildUser= \
		-X github.com/prometheus/common/version.BuildDate=$(shell date +%FT%T%z) -s -w \
	"

export PMM_RELEASE_PATH ?= .

release:          ## Build release binary
	go build $(GO_BUILD_LDFLAGS) -o $(PMM_RELEASE_PATH)/mysqld_exporter

dev:              ## Build and copy the binary to PMM container
	GOOS=linux GOARCH=amd64 make release
	docker cp mysqld_exporter pmm-server:/usr/local/percona/pmm/exporters/mysqld_exporter
	docker exec -t --user root pmm-server chown pmm:pmm /usr/local/percona/pmm/exporters/mysqld_exporter

.PHONY: all init style format build test vet tarball docker env-up env-down help default
