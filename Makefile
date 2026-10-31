# Build artefacts for the execution plane.
#
# `claude-box` ships as a standalone binary per platform, so a customer needs
# nothing but the file: no runtime, no Go toolchain, no package manager.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
DIST := dist
# Where a customer binary fetches the browser kernel. Baked in at link time so a
# fresh install is self-bootstrapping; override with `make KERNEL_URL=...`.
KERNEL_URL ?= https://cdn.veynod.com/kernel/camoufox
# `CCE_KERNEL_URL` still wins at runtime.
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.kernelURLDefault=$(KERNEL_URL)

PLATFORMS := darwin/arm64 darwin/amd64 windows/amd64 linux/amd64

.PHONY: all
all: launcher gateway

# Artefacts are named claude-box-<os>-<arch> with os/arch spelled out, because
# the download page and the support scripts both key off the file name.
ARTIFACT_OS := linux=linux darwin=darwin windows=windows
ARTIFACT_ARCH := amd64=x64 arm64=arm64

.PHONY: launcher
launcher: $(DIST)
	@set -e; \
	for platform in $(PLATFORMS); do \
		goos=$${platform%%/*}; goarch=$${platform##*/}; \
		ext=""; [ "$$goos" = "windows" ] && ext=".exe"; \
		name_os=$$(echo $(ARTIFACT_OS) | tr ' ' '\n' | sed -n "s/^$$goos=//p"); \
		name_arch=$$(echo $(ARTIFACT_ARCH) | tr ' ' '\n' | sed -n "s/^$$goarch=//p"); \
		out="$(DIST)/claude-box-$${name_os}-$${name_arch}$$ext"; \
		echo "  build  $$out"; \
		(cd client-launcher && CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch \
			go build -trimpath -ldflags '$(LDFLAGS)' -o "../$$out" .); \
		[ "$$goos" = "windows" ] || chmod +x "$$out"; \
	done

$(DIST):
	@mkdir -p $(DIST)

.PHONY: gateway
gateway: $(DIST)
	@set -e; \
	for platform in $(PLATFORMS); do \
		goos=$${platform%%/*}; goarch=$${platform##*/}; \
		ext=""; [ "$$goos" = "windows" ] && ext=".exe"; \
		name_os=$$(echo $(ARTIFACT_OS) | tr ' ' '\n' | sed -n "s/^$$goos=//p"); \
		name_arch=$$(echo $(ARTIFACT_ARCH) | tr ' ' '\n' | sed -n "s/^$$goarch=//p"); \
		out="$(DIST)/gateway-$${name_os}-$${name_arch}$$ext"; \
		echo "  build  $$out"; \
		(cd gateway && CGO_ENABLED=0 GOOS=$$goos GOARCH=$$goarch \
			go build -trimpath -ldflags '$(LDFLAGS)' -o "../$$out" .); \
	done

.PHONY: test
test:
	cd client-launcher && go vet ./... && go test ./...
	cd gateway && go vet ./... && go test ./...

.PHONY: check
check: test
	@cd client-launcher && test -z "$$(gofmt -l .)" && echo "  gofmt  client-launcher clean"
	@cd gateway && test -z "$$(gofmt -l .)" && echo "  gofmt  gateway clean"

.PHONY: clean
clean:
	rm -rf $(DIST)

.PHONY: version
version:
	@echo $(VERSION)

# Naming and default-injection are contracts with the download page, so they are
# asserted rather than eyeballed: `make dist-check` fails if either regresses.
.PHONY: dist-check
dist-check: launcher
	@set -e; \
	want="claude-box-darwin-arm64 claude-box-darwin-x64 claude-box-linux-x64 claude-box-windows-x64.exe"; \
	got="$$(ls $(DIST) | grep claude-box | tr '\n' ' ' | sed 's/ $$//')"; \
	[ "$$got" = "$$want" ] || { echo "unexpected artefacts: $$got"; exit 1; }; \
	for file in $(DIST)/claude-box-*; do \
		case "$$file" in *.exe) continue;; esac; \
		strings "$$file" | grep -q "$(KERNEL_URL)" || { echo "no kernel default in $$file"; exit 1; }; \
	done
	@echo "  dist   names and kernel default OK"
