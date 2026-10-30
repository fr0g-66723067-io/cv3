# cv3 — offline NVD search: CVE + CVSS + CPE + CWE.
#
# One binary over one SQLite database (FTS5, pure Go, no cgo). A full sync is
# built into a sibling file and renamed into place, so an interrupted sync never
# damages a working database.

GO ?= go
BIN ?= cv3

.PHONY: all build vet test bench fmt check clean

all: check vet test

build:
	$(GO) build -o $(BIN) ./cmd/cv3

vet:
	$(GO) vet ./...

test:
	$(GO) vet ./...
	$(GO) test ./...
	$(GO) test -race ./...

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./...

fmt:
	$(GO) fmt ./...

# Formatting as a gate rather than a fix: `fmt` rewrites the tree, so `all`
# needs a target that fails on an unformatted file instead of silently
# repairing it.
check:
	@test -z "$$(gofmt -l .)" || { echo "unformatted files (gofmt -l .):"; gofmt -l .; exit 1; }

clean:
	$(GO) clean -testcache
	rm -f $(BIN)
