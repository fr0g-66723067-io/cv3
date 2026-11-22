# cv3

Offline search over the complete CVE corpus: CVE metadata, CVSS scores and
vectors, CPE applicability and CWE classification, for every CVE the CVE
Program knows about — including the ones NVD never enriched.

```
cv3 sync      # full build of the database (network, 10-30 min)
cv3 update    # apply cvelistV5 hourly deltas + NVD modified/recent feeds
cv3 search    # full-text + structured filters
cv3 get       # one or more records, every source merged
cv3 cpe       # which CVEs affect vendor/product at version X
cv3 cwe       # CWE catalog + CVE counts
cv3 stats     # corpus size, coverage, source watermarks
cv3 serve     # local JSON API on 127.0.0.1:8080
```

## Install

Every tag publishes five static binaries and `SHA256SUMS`; replace `vX.Y.Z` with
the newest tag. [docs/release.md](docs/release.md) documents the release process.

```sh
# released binary (linux/amd64 shown; all five targets are on the release)
curl -LO https://github.com/fr0g-66723067-io/cv3/releases/download/vX.Y.Z/cv3_vX.Y.Z_linux_amd64
curl -LO https://github.com/fr0g-66723067-io/cv3/releases/download/vX.Y.Z/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Go 1.27.3 or newer (the `go` directive in `go.mod`); no cgo, no external
service, one dependency (`modernc.org/sqlite`, FTS5 compiled in):

```sh
go install github.com/fr0g-66723067-io/cv3/cmd/cv3@latest   # or: make install
cv3 sync      # ~900 MB download, ~21 min, 2.4 GiB database
cv3 stats
```

## Build, test and install

```
make build          # ./cv3
make check vet test
make bench
make install        # binary -> ~/.local/bin, database -> ~/.local/share/cv3/cv3.db
make uninstall      # binary only; the database is left in place
```

`make install` puts both halves where the code looks by default: the binary on
PATH and the database at the resolved default path (`$XDG_DATA_HOME/cv3/cv3.db`,
else `~/.local/share/cv3/cv3.db`). A database built in a checkout
(`./data/cv3.db`) is moved into place; an existing database at the destination is
never overwritten.

Both locations are selectable:

```
make install PREFIX=/opt/cv3                 # binary -> /opt/cv3/bin
make install DBPATH=/srv/cv3/cv3.db          # database elsewhere; export CV3_DB=...
make install SRCDB=/backup/cv3.db            # ingest a database from elsewhere
```

The resolution order at run time is `-db`, then `$CV3_DB`, then
`$XDG_DATA_HOME/cv3/cv3.db`, then `~/.local/share/cv3/cv3.db`. The download cache
lives beside the database in `cache/`.

## Data sources

| Source | Role | Size |
|---|---|---|
| [cvelistV5](https://github.com/CVEProject/cvelistV5) daily all-CVEs release | complete corpus, CNA CVSS/CWE, ADP CPEs | 647 MB zip, streamed |
| [NVD CVE 2.0 feeds](https://nvd.nist.gov/vuln/data-feeds) 2002..current year, `recent`, `modified` | NVD CVSS, CPE applicability with version ranges, KEV, `vulnStatus` | 250 MB gz total |
| [CWE catalog](https://cwe.mitre.org/data/downloads.html) | CWE names, descriptions, parents | 2.1 MB zip |

Nothing is extracted to disk: the zip and gzip streams are parsed in place. The
daily all-CVEs asset is itself a zip containing `cves.zip`, so that one nested
archive is unwrapped through a temporary file in the cache directory. The
resulting database is expected to be 2-3 GiB. On unix, `cv3 sync` refuses to
start with less than 8 GiB free in the database directory; on Windows there is
no pre-check, and a short disk fails at the first write instead.

Downloads land in `<db dir>/cache` and are reused: an interrupted `cv3 sync`
resumes where it stopped instead of fetching 900 MB again. Pass `-refresh` to
re-download anyway, and `-keep-cache` to keep the archives after a successful
run. NVD serves roughly 200 KB/s per connection, so the feeds are prefetched in
parallel while the cvelistV5 archive is parsed.

The rolling feeds are occasionally unavailable upstream (measured 2026-10-31:
`nvdcve-2.0-modified.json.gz` answered 404 for a period while `-recent.json.gz`
answered 200). `cv3 update` reports that as a warning and still applies
everything else, because a missing rolling feed costs freshness, not
completeness.

NVD feeds lag publication (measured 2026-10-30: 390 of 2 514 recently changed
`CVE-2026-*` ids were absent from the NVD 2026 feed). Those CVEs still appear in
cv3, built from cvelistV5 alone, with `cv3 search -no-nvd` listing exactly the
unenriched remainder.

## Precedence

cvelistV5 creates the base record, NVD overlays it: NVD wins for summary,
published/modified times and `vulnStatus`; cvelistV5 wins for record state. Per
CVSS version the order is NVD-primary, NVD-secondary, CNA, ADP. CPE match rows
from both sources are kept and tagged with their source. The representative
score (`best_score`) is taken from the highest CVSS version present
(v4.0 > v3.1 > v3.0 > v2.0), so `-severity` and `-min-score` mean the same
thing for every row.

## Searching

```
cv3 search openssl heartbleed            # AND of terms, bm25 ranked
cv3 search -or "use-after-free" overflow
cv3 search -severity critical -year 2024 -limit 5
cv3 search -cwe CWE-79 -vendor openssl
cv3 search -kev -min-score 7
cv3 search -no-nvd                       # only records NVD never enriched
```

Structured filters: `-severity -min-score -max-score -cvss -cwe -vendor
-product -year -state -status -kev -no-nvd -after -before -sort -limit -offset
-or`. Every query command accepts `-json`, as do `sync` and `update`; `serve`
answers JSON only, and `version`/`help` take no flags. `-limit` is capped at 500
on every command. `cv3 get -json` with several ids emits one indented envelope
per record, back to back: a JSON stream that `jq` reads as a sequence (a
line-oriented parser will not).

```
cv3 get CVE-2024-3094
cv3 cpe -vendor tukaani -product xz -version 5.6.1
cv3 cpe -cpe cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*
cv3 cwe CWE-79
cv3 cwe -search injection
cv3 stats -severity critical,high        # corpus figures for those bands only
```

`cv3 stats -severity` scopes every CVE-derived figure — records, enrichment,
state, KEV, references, CPE matches, CNA products, FTS rows, and the year and
severity breakdowns — to the listed bands; the CWE catalog size and the database
metadata stay global. `-severity` accepts `none, low, medium, high, critical,
unknown`, where `unknown` is a record with no CVSS metric (the band `cv3 stats`
labels that way), and repeatable like the search filter.

`cv3 cpe -version` evaluates NVD version ranges (`versionStartIncluding`,
`versionEndExcluding`, ...) and exact CPE versions. Specify `-product` when you
know it: a vendor-only query has to rank every CVE of that vendor and costs
around a second for a vendor as large as `linux`, while a vendor+product lookup
is a 30 ms index seek. CNA-only product matches
carry no usable version semantics (upstream uses git hashes and
`versionType: custom`), so they are reported as `unversioned` rather than
guessed at.

## HTTP API

```
cv3 serve [-addr 127.0.0.1:8080]
```

Read-only JSON, same schema as `-json` (`"schemaVersion": "1"`):

```
GET /healthz
GET /v1/search?q=&severity=&minScore=&maxScore=&cvss=&cwe=&vendor=&product=&year=&state=&status=&kev=&noNvd=&after=&before=&or=&sort=&limit=&offset=
GET /v1/cve/{id}
GET /v1/cpe?vendor=&product=&version=&part=&cpe=&limit=
GET /v1/cwe/{id}
GET /v1/cwe?q=
GET /v1/stats?severity=
```

## Exit codes

`0` success, `1` no results / id not found, `2` usage error, `3` database or
data error.

## Versioning and stability

cv3 is versioned with semantic import versioning: `v0.x` releases declare no
compatibility promise, and a tag is the release unit — `go install
github.com/fr0g-66723067-io/cv3/cmd/cv3@v0.2.0` pins the CLI, the JSON schema and
the database schema together. `@latest` resolves to the newest tag; a commit on
`main` past that tag is a pseudo-version, not a release. Every tag's notes live
in [CHANGELOG.md](CHANGELOG.md); [docs/release.md](docs/release.md) is the
release process, and every tag publishes five static binaries plus
`SHA256SUMS`.

Two constants come from the data rather than this module's code:

* **Go 1.27.3** builds the CLI (the `go` directive in `go.mod`); the single
  dependency is `modernc.org/sqlite` (pure Go, FTS5 compiled in, no cgo, no
  external service).
* **The corpus is not vendored.** `cv3 sync` downloads about 900 MB from NVD,
  the CVE Program and MITRE and builds a 2.4 GiB database; a tag works against
  whatever upstream snapshot the operator syncs, and `cv3 stats` reports the
  exact watermarks it holds.

What a `v0.x` minor bump may change without a major bump: the CLI's output text
and flags, the JSON payloads (the envelope carries `"schemaVersion": "1"`), the
SQLite schema (rebuilt by `cv3 sync`; an older binary refuses a newer database),
and which upstream feeds are ingested. Nothing here is deprecated: there are no
shims, aliases or compatibility re-exports to carry.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Copyright 2026 fr0g <fr0g@66723067.io>
(see [NOTICE](NOTICE)).

### Attribution

cv3 ingests three upstream datasets and reproduces excerpts of each in `testdata/`:

* **NVD CVE 2.0 feeds** — <https://nvd.nist.gov/vuln/data-feeds>. NVD data is
  created by employees of the National Institute of Standards and Technology
  (NIST), an agency of the Federal Government. Pursuant to title 17 United States
  Code Section 105, works of NIST employees are not subject to copyright
  protection in the United States. This data/work may be subject to foreign
  copyright.
* **CVE Records (cvelistV5)** — <https://github.com/CVEProject/cvelistV5>, published
  by the CVE Program under its terms of use at
  <https://www.cve.org/Legal/TermsOfUse>. CVE is a registered trademark and the
  CVE logo is a trademark of The MITRE Corporation.
* **CWE catalog** — <https://cwe.mitre.org/>. CWE™ is free to use by any
  organization or individual for any research, development, and/or commercial
  purposes; a copy must reproduce MITRE's copyright designation and the CWE Terms
  of Use. Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF and the
  CWE logo are trademarks of The MITRE Corporation.

No upstream dataset is redistributed: every database is built locally by
`cv3 sync`.
