# cv3

Offline search over the complete CVE corpus: CVE metadata, CVSS scores and
vectors, CPE applicability and CWE classification, for every CVE the CVE
Program knows about — including the ones NVD never enriched.

```
cv3 sync      # full build of the database (network, 10-30 min)
cv3 update    # apply cvelistV5 hourly deltas + NVD modified/recent feeds
cv3 search    # full-text + structured filters
cv3 get       # one record, every source merged
cv3 cpe       # which CVEs affect vendor/product at version X
cv3 cwe       # CWE catalog + CVE counts
cv3 stats     # corpus size, coverage, source watermarks
cv3 serve     # local JSON API on 127.0.0.1:8080
```

Build and test:

```
make build      # ./cv3
make check vet test
make bench
```

## Data sources

| Source | Role | Size |
|---|---|---|
| [cvelistV5](https://github.com/CVEProject/cvelistV5) daily all-CVEs release | complete corpus, CNA CVSS/CWE, ADP CPEs | 647 MB zip, streamed |
| [NVD CVE 2.0 feeds](https://nvd.nist.gov/vuln/data-feeds) 2002..current year, `recent`, `modified` | NVD CVSS, CPE applicability with version ranges, KEV, `vulnStatus` | 250 MB gz total |
| [CWE catalog](https://cwe.mitre.org/data/downloads.html) | CWE names, descriptions, parents | 2.1 MB zip |

Nothing is extracted to disk: the zip and gzip streams are parsed in place. The
daily all-CVEs asset is itself a zip containing `cves.zip`, so that one nested
archive is unwrapped through a temporary file in the cache directory. The
resulting database is expected to be 2-3 GiB; `cv3 sync` refuses to start with
less than 8 GiB free in the database directory.

Downloads land in `<db dir>/cache` and are reused: an interrupted `cv3 sync`
resumes where it stopped instead of fetching 900 MB again. Pass `-refresh` to
re-download anyway, and `-keep-cache` to keep the archives after a successful
run. NVD serves roughly 200 KB/s per connection, so the feeds are prefetched in
parallel while the cvelistV5 archive is parsed.

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
-or`. Every command accepts `-json`.

```
cv3 get CVE-2024-3094
cv3 cpe -vendor tukaani -product xz -version 5.6.1
cv3 cpe -cpe cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*
cv3 cwe CWE-79
cv3 cwe -search injection
```

`cv3 cpe -version` evaluates NVD version ranges (`versionStartIncluding`,
`versionEndExcluding`, ...) and exact CPE versions. CNA-only product matches
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
GET /v1/search?q=&severity=&minScore=&maxScore=&cvss=&cwe=&vendor=&product=&year=&state=&status=&kev=&noNvd=&sort=&limit=&offset=
GET /v1/cve/{id}
GET /v1/cpe?vendor=&product=&version=&part=&cpe=&limit=
GET /v1/cwe/{id}
GET /v1/cwe?q=
GET /v1/stats
```

## Exit codes

`0` success, `1` no results / id not found, `2` usage error, `3` database or
data error.

## Licensing

NVD data is public domain (US Government work). cvelistV5 is published under the
CVE Program's terms (MITRE). The CWE catalog is copyright MITRE, distributed
under the CWE terms of use. No upstream data is redistributed by this repository.
