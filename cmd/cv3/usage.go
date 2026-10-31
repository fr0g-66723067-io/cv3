package main

const usage = `cv3 — offline NVD search: CVE + CVSS + CPE + CWE.

Usage:
  cv3 sync   [-db PATH] [-cache DIR] [-keep-cache] [-refresh] [-workers N] [-years A-B] [-quiet] [-json]
  cv3 update [-db PATH] [-cache DIR] [-keep-cache] [-refresh] [-quiet] [-json]
  cv3 search [flags] <terms...>
  cv3 get    <CVE-ID>... [-json]
  cv3 cpe    [-vendor V] [-product P] [-version X] [-part a|o|h] [-cpe CPE] [-limit N] [-json]
  cv3 cwe    [<CWE-ID>] [-search TERMS] [-limit N] [-json]
  cv3 stats  [-json]
  cv3 serve  [-addr 127.0.0.1:8080]
  cv3 version | help

search flags:
  -severity low,medium,high,critical   -min-score F   -max-score F
  -cvss v2|v3.0|v3.1|v4.0              -cwe CWE-79 (repeatable)
  -vendor V (repeatable)               -product P (repeatable)
  -year 2024 | -year 2020-2024         -state PUBLISHED,REJECTED,RESERVED
  -status "Awaiting Analysis"          -kev   -no-nvd
  -after YYYY-MM-DD   -before YYYY-MM-DD
  -sort relevance|score|date|id        -limit 20   -offset 0   -or   -json

Database path: -db, else $CV3_DB, else $XDG_DATA_HOME/cv3/cv3.db, else
~/.local/share/cv3/cv3.db. 'make install' puts the database at that default.
The download cache lives beside it in cache/.

Exit codes: 0 success, 1 no results / not found, 2 usage error, 3 database or
data error.
`
