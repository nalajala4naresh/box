PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
GOARCH ?= $(shell go env GOARCH)
GOOS   ?= $(shell go env GOOS)
# krun_net enables libkrun-go's virtio-net bindings (libkrun built with NET=1).
TAGS   ?= krun_net
AGENT  := internal/agentbin/bin/box-agent-linux-$(GOARCH)
# Not ./box: codesign treats an executable named like its directory (this
# repo is box/) as a bundle and tries to seal every file beside it.
BIN    := bin/box

$(BIN): FORCE
FORCE:

.PHONY: build agent install test vet fmt-check clean

build: $(BIN)

# The guest agent is a static Linux binary embedded into box.
agent:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath -ldflags='-s -w' -o $(AGENT) ./cmd/box-agent

$(BIN): agent
	go build -trimpath -tags $(TAGS) -o $(BIN) ./cmd/box
ifeq ($(GOOS),darwin)
	# Hypervisor.framework requires the com.apple.security.hypervisor entitlement.
	codesign --entitlements entitlements.plist --force -s - $(BIN)
endif

install: build
	install -d $(BINDIR)
	install -m755 $(BIN) $(BINDIR)/box
ifeq ($(GOOS),darwin)
	codesign --entitlements entitlements.plist --force -s - $(BINDIR)/box
endif

test: agent
	go test -tags $(TAGS) ./...

vet: agent
	go vet -tags $(TAGS) ./...
	GOOS=linux GOARCH=$(GOARCH) go vet ./cmd/box-agent

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l .; exit 1)

clean:
	rm -rf bin $(AGENT)
