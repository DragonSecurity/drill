SHELL := /bin/bash

PROJECT_NAME ?= drill
PKG          ?= drill
CMD_PKG      ?= $(PKG)/cmd
DIST         ?= dist

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo 0000000)
DATE    ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w -X $(CMD_PKG).Version=$(VERSION) -X $(CMD_PKG).Commit=$(COMMIT) -X $(CMD_PKG).Date=$(DATE)
GOFLAGS ?= -trimpath
CGO_ENABLED ?= 0

# Common platforms. Edit as needed.
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build clean build-all linux darwin windows print-version

all: build

ensure-dist:
	@mkdir -p $(DIST)

print-version:
	@echo "version=$(VERSION) commit=$(COMMIT) date=$(DATE)"

build: ensure-dist
	CGO_ENABLED=$(CGO_ENABLED) go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(PROJECT_NAME) .

clean:
	rm -rf $(DIST)

# Build for all PLATFORMS (arm & amd64 included for each OS listed)
build-all: clean ensure-dist
	@set -e; for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		ext=$$( [ $$os = windows ] && echo .exe || echo "" ); \
		out="$(DIST)/$(PROJECT_NAME)_$${os}_$${arch}$$ext"; \
		echo ">> building $$out"; \
		CGO_ENABLED=$(CGO_ENABLED) GOOS=$$os GOARCH=$$arch \
			go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $$out .; \
	done

# Convenience bundles
linux: ensure-dist
	$(MAKE) build-all PLATFORMS="linux/amd64 linux/arm64"

darwin: ensure-dist
	$(MAKE) build-all PLATFORMS="darwin/amd64 darwin/arm64"

windows: ensure-dist
	$(MAKE) build-all PLATFORMS="windows/amd64 windows/arm64"
