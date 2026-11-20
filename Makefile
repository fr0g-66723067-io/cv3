# cv3 — offline NVD search: CVE + CVSS + CPE + CWE.
#
# One binary over one SQLite database (FTS5, pure Go, no cgo). A full sync is
# built into a sibling file and renamed into place, so an interrupted sync never
# damages a working database.

GO ?= go
BIN ?= cv3

# install layout. The database default below is the exact path the code resolves
# when neither -db nor $CV3_DB is set, so `cv3 sync`/`cv3 stats` need no flags
# after `make install`.
PREFIX   ?= $(HOME)/.local
BINDIR   ?= $(PREFIX)/bin
DATAHOME ?= $(if $(XDG_DATA_HOME),$(XDG_DATA_HOME),$(HOME)/.local/share)
DATADIR  ?= $(DATAHOME)/cv3
DBPATH   ?= $(DATADIR)/cv3.db
# A database and download cache built in the checkout.
SRCDB    ?= ./data/cv3.db
SRCCACHE ?= $(dir $(SRCDB))cache
CACHEDIR ?= $(DATADIR)/cache

# The tag is the release unit; -dirty and the short commit keep a local build
# honest. Both fall back when git is unavailable (module cache, tarball).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS ?= -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build install uninstall vet test bench fmt check clean

all: check vet test

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/cv3

# Installs the binary and puts the database at the path the code expects. A
# database already in place is never overwritten: an existing corpus is the
# operator's, and re-syncing is a separate, explicit action.
#
#   make install                            # ~/.local/bin + ~/.local/share/cv3/cv3.db
#   make install DBPATH=/srv/cv3/cv3.db     # custom location (then set CV3_DB)
#   make install SRCDB=/tmp/db/cv3.db       # ingest a database from elsewhere
#
# DESTDIR applies to the binary only: the database is user data, not package
# content.
install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)
	@set -e; \
	if [ -f '$(DBPATH)' ]; then \
		echo "database: keeping existing $(DBPATH)"; \
	elif [ -f '$(SRCDB)' ]; then \
		install -d '$(dir $(DBPATH))'; \
		mv -f '$(SRCDB)' '$(DBPATH)'; \
		echo "database: moved $(SRCDB) -> $(DBPATH)"; \
	else \
		echo "database: none yet; run '$(BIN) sync' to build $(DBPATH)"; \
	fi
	@if [ -d '$(SRCCACHE)' ] && [ ! -e '$(CACHEDIR)' ]; then \
		install -d '$(dir $(CACHEDIR))'; \
		mv -f '$(SRCCACHE)' '$(CACHEDIR)'; \
		echo "cache: moved $(SRCCACHE) -> $(CACHEDIR)"; \
	fi
	@echo "installed $(DESTDIR)$(BINDIR)/$(BIN)"
	@if [ '$(DBPATH)' != '$(DATAHOME)/cv3/cv3.db' ]; then \
		echo "note: custom database path; export CV3_DB='$(DBPATH)'"; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(BIN)
	@echo "database kept at $(DBPATH); remove it manually if you want the space back"

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
