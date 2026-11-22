#!/bin/sh
# Artifact-level gate: version, help, and the documented exit code for a
# database that is not there (3, not a panic and not a zero).
set -eu
bin=${1:?usage: smoke.sh BINARY}
out=$("$bin" version)
case "$out" in cv3\ *) : ;; *) echo "smoke: version printed '$out'" >&2; exit 1 ;; esac
"$bin" help >/dev/null
set +e
"$bin" stats -db /nonexistent/cv3-smoke/cv3.db >/dev/null 2>&1
status=$?
set -e
[ "$status" -eq 3 ] || { echo "smoke: stats on a missing database exited $status, want 3" >&2; exit 1; }
echo "   version, help and the missing-database exit code are correct"
