# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.4] - 2026-11-20

### Changed

- **Release-notes correction; no code change.** The 0.1.3 entry described the
  `-limit` change as documentation only, but 0.1.3 shipped the behaviour change
  too; the entry now says so. Nothing in the module differs from `v0.1.3`
  except this file.

## [0.1.3] - 2026-11-20

### Fixed

- **`cv3 help` matches the flags every command takes.** `-db PATH` is listed on
  `search`, `get`, `cpe`, `cwe`, `stats` and `serve` (it was only on `sync` and
  `update`), `-workers N` is listed on `cv3 update` (it was accepted and honored
  but undocumented), `-years` now says it is `cv3 sync`-only and that
  `cv3 update` rejects it, and `-state` names `UNKNOWN`, which cvelistV5 records
  without a state and NVD-only rows carry.
- **The README stops claiming every command takes `-json`**: `serve` answers JSON
  only, `version`/`help` take no flags. The documented `/v1/search` parameters
  gain `after`, `before` and `or`, which the server already accepted. Its
  versioning paragraph now says `@latest` resolves to the newest tag and that a
  commit on `main` past it is a pseudo-version, instead of implying `@latest`
  itself is one.
- **`cv3 cwe -search` obeys the 500-row page cap.** A limit above 500 used to be
  treated as "use the default" and returned 25 rows; every listing query now
  shares `store.ClampLimit`, so `-limit 1000` returns up to 500 rows the way
  `search` and `cpe` already did.
- **`cv3 help` and README name the `none` severity band**, which the store accepts
  alongside `low,medium,high,critical`, and document the 500-row cap.
- **`cv3 get` is documented as taking one or more ids**, and its `-json` mode as
  one envelope per record, concatenated into a JSON stream that `jq` reads as a
  sequence.

## [0.1.2] - 2026-11-20

### Fixed

- **`cv3 version` names the tag on `go install` builds.** Both values came only
  from `-ldflags`, so a binary installed with `go install …@v0.1.1` reported
  `cv3 dev (none)`. The command now falls back to the module version and VCS
  revision Go embeds in the binary; the Makefile's stamps still win, and a dirty
  local build says so.

## [0.1.1] - 2026-11-20

### Fixed

- **The module builds on Windows again.** The free-space guard run at the start of
  `cv3 sync` used `syscall.Statfs`, which does not exist there; it now lives
  behind `//go:build unix` with a no-op elsewhere, so `go install` and `go build`
  work on every platform Go supports. CI cross-vets `windows/amd64` and
  `darwin/arm64` so a platform-specific import cannot land unnoticed again.
- **The documented Go floor matches `go.mod`**: Go 1.27.3, not "1.27 or newer".

## [0.1.0] - 2026-11-20

### Added

- **Offline search over the CVE corpus with CVSS, CPE and CWE.** `cv3 sync` builds
  a 2.4 GiB SQLite database from the cvelistV5 daily release, the NVD CVE 2.0
  feeds and the MITRE CWE catalog; `cv3 update` applies cvelistV5 hourly deltas
  plus the rolling NVD `modified`/`recent` feeds. No upstream dataset is
  redistributed: every database is built locally from the sources.
- **Seven commands** — `sync`, `update`, `search`, `get`, `cpe`, `cwe`, `stats` —
  plus `serve`, a read-only JSON API on `127.0.0.1:8080`. `search` takes free text
  (FTS5, bm25) and the filters `-severity`, `-min-score`, `-max-score`, `-cvss`,
  `-cwe`, `-vendor`, `-product`, `-year`, `-state`, `-status`, `-kev`, `-no-nvd`,
  `-after`, `-before`, `-sort`; every command accepts `-json`, and the CLI and
  HTTP surfaces share one schema (`"schemaVersion": "1"`).
- **One merged corpus.** cvelistV5 creates the base record; NVD overlays CPE
  applicability with version ranges, NVD CVSS metrics, KEV flags and
  `vulnStatus`, so records NVD never enriched keep their CNA CVSS, CWE and CPE.
  The representative score is the highest CVSS version present (v4.0 > v3.1 >
  v3.0 > v2.0); CWE identifiers resolve through the catalog.
- **Pure-Go, no cgo, one dependency** (`modernc.org/sqlite` with FTS5 compiled
  in). The query path mmaps the database and needs no service; a failed sync
  never damages a working database, because the build is renamed into place.

### Measured

- Corpus of 2026-10-31: 417 488 CVEs, 3 535 274 CPE match rows, 694 190 CNA
  products, 984 CWE entries, 1 354 916 references, 2.36 GiB on disk. Full sync
  21m32s; incremental update 29s–4m9s depending on the rolling feeds.
- `cv3 search` 5–14 ms wall for a term query, `cv3 get` under 10 ms,
  `cv3 cpe -vendor … -product … -version …` 30 ms.
