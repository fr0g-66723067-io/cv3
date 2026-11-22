package main

const usage = `cv3 — offline NVD search: CVE + CVSS + CPE + CWE.

Usage:
  cv3 sync   [-db PATH] [-cache DIR] [-keep-cache] [-refresh] [-workers N] [-years A-B] [-quiet] [-json]
  cv3 update [-db PATH] [-cache DIR] [-keep-cache] [-refresh] [-workers N] [-quiet] [-json]
  cv3 search [-db PATH] [flags] <terms...>
  cv3 get    [-db PATH] <CVE-ID>... [-json]
  cv3 cpe    [-db PATH] [-vendor V] [-product P] [-version X] [-part a|o|h] [-cpe CPE] [-limit N] [-json]
  cv3 cwe    [-db PATH] [<CWE-ID>] [-search TERMS] [-limit N] [-json]
  cv3 stats  [-db PATH] [-severity S] [-json]
  cv3 serve  [-db PATH] [-addr ADDR]
  cv3 version | help

-years A-B is a 'cv3 sync' flag: it selects which NVD year feeds are ingested.
'cv3 update' follows the corpus watermarks, applies only the hourly cvelistV5
deltas and the rolling NVD feeds, and rejects -years.

search flags:
  -db PATH                                  database path
  -severity none,low,medium,high,critical,unknown
  -min-score F   -max-score F
  -cvss v2|v3.0|v3.1|v4.0                   -cwe CWE-79 (repeatable)
  -vendor V (repeatable)                    -product P (repeatable)
  -year 2024 | -year 2020-2024
  -state PUBLISHED,REJECTED,RESERVED,UNKNOWN
  -status "Awaiting Analysis"               -kev   -no-nvd
  -after YYYY-MM-DD   -before YYYY-MM-DD
  -sort relevance|score|date|id             -limit 20   -offset 0   -or   -json

-limit is capped at 500 on every command. -json on 'cv3 get' emits one envelope
per id, concatenated (a JSON stream; jq reads it as a sequence). 'unknown' is a
record with no CVSS metric; 'cv3 stats -severity' takes the same bands and scopes
every CVE-derived figure to them.

'-addr' defaults to 127.0.0.1:8080. A non-loopback bind requires
$CV3_SERVE_TOKEN; clients then send 'Authorization: Bearer <token>'.

Database path: -db, else $CV3_DB, else $XDG_DATA_HOME/cv3/cv3.db, else
~/.local/share/cv3/cv3.db. 'make install' puts the database at that default.
The download cache lives beside it in cache/.

Exit codes: 0 success, 1 no results / not found, 2 usage error, 3 database or
data error.
`
