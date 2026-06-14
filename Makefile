APP=epdg
BIN_DIR=bin
CMD=./cmd/epdg
GOCACHE?=/tmp/vectorcore-epdg-gocache
GOMODCACHE?=/tmp/vectorcore-epdg-gomodcache
GOENV=GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)
VERSION?=0.1.5d
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: build tidy test clean install

build:
	install -d $(BIN_DIR)
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP) $(CMD)

tidy:
	$(GOENV) go mod tidy

test:
	$(GOENV) go test ./...

clean:
	rm -rf $(BIN_DIR)

install: build
	install -d /opt/vectorcore/epdg/bin
	install -d /etc/vectorcore/epdg
	install -d /var/log/vectorcore/epdg
	install -m 0755 $(BIN_DIR)/$(APP) /opt/vectorcore/epdg/bin/$(APP)
