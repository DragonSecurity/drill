# -------------------------
# Variables
# -------------------------

UI_VERSION := $(shell cat web/drill/package.json | grep version | head -1 | awk -F: '{ print $$2 }' | sed 's/[\",]//g' | tr -d '[[:space:]]')
VERSION_PATH := github.com/DragonSecurity/drill/internal/version
GIT_COMMIT := $(shell git rev-list -1 HEAD)
BUILD_DATE := $(shell date +%FT%T%z)
RELEASE_DIR := build/release

LDFLAGS := -ldflags "-X $(VERSION_PATH).GitCommit=$(GIT_COMMIT) -X $(VERSION_PATH).UIVersion=$(UI_VERSION) -X $(VERSION_PATH).BuildDate=$(BUILD_DATE)"

# -------------------------
# Target matrices
# -------------------------

OS := darwin freebsd linux windows
ARCH := amd64 arm arm64
EXCLUDE := darwin/arm windows/arm

# Build list of allowed os/arch pairs (space-separated strings like darwin/amd64)
RELEASE_PAIRS := $(foreach os,$(OS),$(foreach arch,$(ARCH),\
	$(if $(filter $(os)/$(arch),$(EXCLUDE)),,$(os)/$(arch))\
))

# Release artifacts we will build
RELEASE_BINS := \
  $(foreach p,$(RELEASE_PAIRS),$(RELEASE_DIR)/drill_$(subst /,_,$(p))) \
  $(foreach p,$(RELEASE_PAIRS),$(RELEASE_DIR)/drill-server_$(subst /,_,$(p)))

# -------------------------
# Phony targets
# -------------------------

.PHONY: build build_server build_client build_ui_landing wire static_landing install_dependencies clean release

# -------------------------
# Default build (host platform)
# -------------------------

build: static_landing wire build_server build_client

build_server:
	@mkdir -p build
	@echo "→ building drill-server (host)"
	@CGO_ENABLED=0 go build $(LDFLAGS) -o ./build/drill-server ./cmd/drill-server

build_client:
	@mkdir -p build
	@echo "→ building drill (host)"
	@CGO_ENABLED=0 go build $(LDFLAGS) -o ./build/drill ./cmd/drill

# -------------------------
# UI / codegen / assets
# -------------------------

build_ui_landing:
	@if [ ! -d "web/drill/dist" ]; then \
		echo "→ building UI landing"; \
		cd web/drill && yarn build; \
	fi

wire:
	@echo "→ running wire"
	@wire ./cmd/drill-server

static_landing: build_ui_landing
	@if [ ! -r "internal/ui/landing/static.go" ]; then \
		echo "→ embedding static landing (statik)"; \
		statik -dest ./internal/ui -p landing -src ./web/drill/dist; \
	fi

install_dependencies:
	@echo "→ installing Go/YARN tools"
	@go get github.com/jkuri/statik github.com/google/wire/cmd/...
	@go install github.com/jkuri/statik
	@go install github.com/google/wire/cmd/...
	@cd web/drill && yarn install

clean:
	@echo "→ cleaning"
	@rm -rf build/ internal/ui web/drill/dist

# -------------------------
# Multi-arch release (no gox)
# -------------------------

release: static_landing wire $(RELEASE_BINS)
	@echo "✓ release artifacts in $(RELEASE_DIR)"

# -------- rules generator (no empty pairs, honors EXCLUDE) --------
define GEN_RULES
$(RELEASE_DIR)/drill_$(1)_$(2):
	@mkdir -p $(RELEASE_DIR)
	@echo "→ building drill for $(1)/$(2)"
	@CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build $(LDFLAGS) -o $$@ ./cmd/drill

$(RELEASE_DIR)/drill-server_$(1)_$(2):
	@mkdir -p $(RELEASE_DIR)
	@echo "→ building drill-server for $(1)/$(2)"
	@CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build $(LDFLAGS) -o $$@ ./cmd/drill-server
endef

# Instantiate for each allowed pair
$(foreach os,$(OS),$(foreach arch,$(ARCH),\
  $(if $(filter $(os)/$(arch),$(EXCLUDE)),,\
    $(eval $(call GEN_RULES,$(os),$(arch)))\
  )\
))
