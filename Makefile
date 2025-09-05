APP := drill
CARGO := cross
LINUX := x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl
.PHONY: linux
linux: $(LINUX)
$(LINUX):
	$(CARGO) build --release --target $@
