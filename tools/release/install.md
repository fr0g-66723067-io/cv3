```sh
# released binary (linux/amd64 shown; all five targets are on the release)
curl -LO https://github.com/fr0g-66723067-io/cv3/releases/download/v@VERSION@/cv3_v@VERSION@_linux_amd64
curl -LO https://github.com/fr0g-66723067-io/cv3/releases/download/v@VERSION@/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# or install the command from the module
go install github.com/fr0g-66723067-io/cv3/cmd/cv3@v@VERSION@
cv3 sync
```
