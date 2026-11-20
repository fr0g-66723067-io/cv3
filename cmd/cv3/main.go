// Command cv3 answers offline CVE queries from a local database built by
// `cv3 sync`. See the usage text for the command set.
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
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return exitOK
	case "version":
		v, c := buildStamp()
		fmt.Fprintf(stdout, "cv3 %s (%s)\n", v, c)
		return exitOK
	case "sync":
		return runSync(rest, stdout, stderr)
	case "update":
		return runUpdate(rest, stdout, stderr)
	case "search":
		return runSearch(rest, stdout, stderr)
	case "get":
		return runGet(rest, stdout, stderr)
	case "cpe":
		return runCPE(rest, stdout, stderr)
	case "cwe":
		return runCWE(rest, stdout, stderr)
	case "stats":
		return runStats(rest, stdout, stderr)
	case "serve":
		return runServe(rest, stdout, stderr)
	}
	fmt.Fprintf(stderr, "cv3: unknown command %q\n", cmd)
	fmt.Fprint(stderr, usage)
	return exitUsage
}
