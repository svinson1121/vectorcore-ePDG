APP=epdg
BIN_DIR=bin
CMD=./cmd/epdg
GOCACHE?=/tmp/vectorcore-epdg-gocache
GOMODCACHE?=/tmp/vectorcore-epdg-gomodcache
GOENV=GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)
VERSION?=0.5.0d
BUILD_DATE?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)

.PHONY: build generate tidy test clean install

build: generate
	install -d $(BIN_DIR)
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP) $(CMD)

generate:
	$(GOENV) go generate ./internal/gtpu/...

tidy:
	$(GOENV) go mod tidy

test:
	$(GOENV) go test ./...

clean:
	rm -rf $(BIN_DIR)
	find internal/gtpu -maxdepth 1 -name '*.o' -delete

install: build
	install -d /opt/vectorcore/epdg/bin
	install -d /etc/vectorcore/epdg
	install -d /var/log/vectorcore/epdg
	install -m 0755 $(BIN_DIR)/$(APP) /opt/vectorcore/epdg/bin/$(APP)
