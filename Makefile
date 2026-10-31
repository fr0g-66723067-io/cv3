# cv3 — offline NVD search: CVE + CVSS + CPE + CWE.
#
# One binary over one SQLite database (FTS5, pure Go, no cgo). A full sync is
# built into a sibling file and renamed into place, so an interrupted sync never
# damages a working database.

GO ?= go
BIN ?= cv3
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin

.PHONY: all build install uninstall vet test bench fmt check clean

all: check vet test

build:
	$(GO) build -o $(BIN) ./cmd/cv3

# Installs the binary on PATH. The database is not part of the install: it is
# already 2.4 GiB, is rebuilt by `cv3 sync`, and lives either in ./data/cv3.db
# (checkout) or under the XDG data directory, so `cv3 stats` finds whichever
# exists without flags.
install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	@echo "installed $(DESTDIR)$(BINDIR)/$(BIN)"
	@echo 'database: ./data/cv3.db in the working directory, else $$XDG_DATA_HOME/cv3/cv3.db' 

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)

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
