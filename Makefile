# Build artefacts for the execution plane.
#
# `claude-box` ships as a standalone binary per platform, so a customer needs
# nothing but the file: no runtime, no Go toolchain, no package manager.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST := dist

PLATFORMS := darwin/arm64 darwin/amd64 windows/amd64 linux/amd64

.PHONY: all
all: launcher gateway

.PHONY: launcher
launcher: $(DIST)
	@set -e; \
	for platform in $(PLATFORMS); do \
		goos=$${platform%%/*}; goarch=$${platform##*/}; \
		ext=""; [ "$$goos" = "windows" ] && ext=".exe"; \
		out="$(DIST)/claude-box-$$goos-$$goarch$$ext"; \
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
		out="$(DIST)/gateway-$$goos-$$goarch$$ext"; \
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
