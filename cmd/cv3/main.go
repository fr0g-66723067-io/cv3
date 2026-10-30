package main

import (
	"fmt"
	"io"
	"os"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "help", "-h", "-help", "--help":
			fmt.Fprint(stdout, usage)
			return 0
		case "version":
			fmt.Fprintf(stdout, "cv3 %s (%s)\n", version, commit)
			return 0
		}
	}
	fmt.Fprintf(stderr, "cv3: unknown command %q\n", firstArg(args))
	fmt.Fprint(stderr, usage)
	return 2
}

const usage = `cv3 — offline NVD search: CVE + CVSS + CPE + CWE.

Usage:
  cv3 sync   [-db PATH] [-cache DIR] [-keep-cache] [-workers N] [-years A-B] [-quiet] [-json]
  cv3 update [-db PATH] [-cache DIR] [-keep-cache] [-quiet] [-json]
  cv3 search [flags] <terms...>
  cv3 get    <CVE-ID>... [-json]
  cv3 cpe    [-vendor V] [-product P] [-version X] [-part a|o|h] [-cpe CPE] [-limit N] [-json]
  cv3 cwe    [<CWE-ID>] [-search TERMS] [-limit N] [-json]
  cv3 stats  [-json]
  cv3 serve  [-addr 127.0.0.1:8080]
  cv3 version | help

Exit codes: 0 success, 1 no results / not found, 2 usage error, 3 database or
data error.
`

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
