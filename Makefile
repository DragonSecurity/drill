# ---- Settings ----
BIN            ?= drill
# Use cross only if both cross and Docker are available & Docker is running
CARGO ?= $(shell command -v cross >/dev/null 2>&1 && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 && echo cross || echo cargo)
LINUX_TARGETS  ?= x86_64-unknown-linux-musl aarch64-unknown-linux-musl
MAC_TARGETS    ?= aarch64-apple-darwin x86_64-apple-darwin
PKG_TARGETS    ?= $(LINUX_TARGETS) $(MAC_TARGETS)
DIST           ?= dist
TAG            ?= v0.0.0-act            # tag used by local act runs

# Where act will stash downloaded/uploaded artifacts locally
ACT_ARTIFACTS  ?= ./.act/artifacts

# Act runner/image + common flags
WORKFLOW       ?= .github/workflows/release.yml
ACT_IMAGE_UBU  ?= catthehacker/ubuntu:act-24.04
ACT_FLAGS      ?= -W $(WORKFLOW) \
                  -P ubuntu-24.04=$(ACT_IMAGE_UBU) \
                  --artifact-server-path $(ACT_ARTIFACTS)

# Optional: provide a token to actually hit the GitHub API during release
# (otherwise the final release step will fail, but build & artifact wiring are still tested)
ACT_SECRET_TOKEN ?=

# Derive owner/repo from git remote (fallback to placeholder)
REPO_FULL_NAME ?= $(shell \
  url=$$(git ls-remote --get-url origin 2>/dev/null || true); \
  if [ -n "$$url" ]; then \
    echo "$$url" \
      | awk -F'[:/]' '{print $$(NF-1)"/"$$NF}' \
      | sed -E 's|\.git$$||'; \
  else \
    echo owner/repo; \
  fi)
# ---- Build (local) ----
.PHONY: linux
linux: $(LINUX_TARGETS)

.PHONY: macos
macos: $(MAC_TARGETS)

$(LINUX_TARGETS):
	$(CARGO) build --release --target $@

$(MAC_TARGETS):
	$(CARGO) build --release --target $@

# ---- Package (local) ----
.PHONY: package
package:
	@set -eu; \
	mkdir -p $(DIST); \
	for tgt in $(PKG_TARGETS); do \
	  outdir="$(DIST)/$$tgt"; \
	  mkdir -p "$$outdir"; \
	  src="target/$$tgt/release/$(BIN)"; \
	  if [ ! -s "$$src" ]; then echo "skip $$tgt (missing $$src)"; continue; fi; \
	  cp "$$src" "$$outdir/"; \
	  test -f README.md && cp README.md "$$outdir/" || true; \
	  ls -1 LICENSE* >/dev/null 2>&1 && cp LICENSE* "$$outdir/" || true; \
	  tarball="$(BIN)-$$tgt.tar.gz"; \
	  tar -C $(DIST) -czf "$$tarball" "$$tgt"; \
	  if command -v shasum >/dev/null 2>&1; then \
	    shasum -a 256 "$$tarball" > "$$tarball.sha256"; \
	  else \
	    sha256sum "$$tarball" > "$$tarball.sha256"; \
	  fi; \
	  echo "Packed $$tarball"; \
	done

# ---- Clean ----
.PHONY: clean
clean:
	rm -rf target $(DIST)

# ---- nektos/act helpers ----
# Generate a minimal push tag event JSON so the release job is eligible to run.
ACT_EVENT := ./.act/tag_event.json

$(ACT_EVENT):
	@mkdir -p ./.act
	@printf '{\n' >  $(ACT_EVENT)
	@printf '  "ref": "refs/tags/%s",\n' "$(TAG)" >> $(ACT_EVENT)
	@printf '  "ref_type": "tag",\n'                      >> $(ACT_EVENT)
	@printf '  "repository": {\n'                         >> $(ACT_EVENT)
	@printf '    "full_name": "%s"\n' "$(REPO_FULL_NAME)" >> $(ACT_EVENT)
	@printf '  }\n'                                       >> $(ACT_EVENT)
	@printf '}\n'                                         >> $(ACT_EVENT)

.PHONY: _act_check
_act_check:
	@command -v act >/dev/null 2>&1 || { echo "ERROR: 'act' not found. Install via: brew install act / scoop install act / etc."; exit 1; }

.PHONY: act-linux
act-linux: _act_check $(ACT_EVENT)
	@# Run ONLY the Linux job(s) locally (fast feedback)
	act push -e $(ACT_EVENT) -j build-linux $(ACT_FLAGS)

.PHONY: act-release
act-release: _act_check $(ACT_EVENT)
	@# Simulate a tagged push and run Linux build + release jobs.
	@# Artifacts are stashed under $(ACT_ARTIFACTS) and downloaded by the release job.
	mkdir -p $(ACT_ARTIFACTS)
	@if [ -n "$(ACT_SECRET_TOKEN)" ]; then \
	  extra="-s GITHUB_TOKEN=$(ACT_SECRET_TOKEN)"; \
	else \
	  extra=""; \
	fi; \
	act push -e $(ACT_EVENT) -j build-linux -j release-linux-only $(ACT_FLAGS) $$extra

.PHONY: act-clean
act-clean:
	rm -rf ./.act

# ---- Helpers ----
.PHONY: help
help:
	@echo "Common targets:"
	@echo "  make linux            Build release binaries for $(LINUX_TARGETS) (uses '$(CARGO)')"
	@echo "  make macos            Build release binaries for $(MAC_TARGETS)"
	@echo "  make package          Package already-built artifacts in $(PKG_TARGETS) (override with PKG_TARGETS=...)"
	@echo "  make clean            Clean target and dist"
	@echo "  make act-linux        Run only the Linux job(s) from the release workflow with nektos/act"
	@echo "  make act-release      Simulate a tagged push and run Linux build + release under act"
	@echo "  make act-clean        Remove act artifacts"
