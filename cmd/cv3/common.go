package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"context"

	"github.com/fr0g-66723067-io/cv3/internal/store"
)

// Exit codes, as documented in usage text.
const (
	exitOK        = 0
	exitNoResults = 1
	exitUsage     = 2
	exitData      = 3
)

func fail(stderr io.Writer, code int, format string, args ...any) int {
	fmt.Fprintf(stderr, "cv3: "+format+"\n", args...)
	return code
}

// listFlag is a repeatable, comma-splitting string flag.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseFlags silences the flag package so only cv3's own text reaches the
// streams. It returns (status, true) when parsing succeeded.
func parseFlags(fs *flag.FlagSet, args []string, stdout, stderr io.Writer) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return exitOK, false
		}
		fmt.Fprintf(stderr, "cv3: %v\n", err)
		fmt.Fprint(stderr, usage)
		return exitUsage, false
	}
	return 0, true
}

// flagName returns the name of a "-name", "--name" or "-name=value" token and
// whether the token already carries its value; a token that is not a flag
// yields "".
func flagName(arg string) (name string, hasValue bool) {
	if len(arg) < 2 || arg[0] != '-' {
		return "", false
	}
	name = strings.TrimPrefix(arg[1:], "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		return name[:i], true
	}
	return name, false
}

// boolFlag reports whether f takes no value.
func boolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

// splitArgs separates flags from positionals so a flag may follow the
// positionals: "cv3 search openssl -kev" parses like "cv3 search -kev openssl".
func splitArgs(fs *flag.FlagSet, args []string) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		name, hasValue := flagName(arg)
		if name == "" && !hasValue {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		if f := fs.Lookup(name); f != nil && !hasValue && !boolFlag(f) && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, positional
}

// anySet reports whether the named flag was given on the command line.
func anySet(fs *flag.FlagSet, names ...string) bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for _, n := range names {
		if set[n] {
			return true
		}
	}
	return false
}

// resolveDB applies the database path precedence.
func resolveDB(flagVal string) (string, error) {
	if flagVal != "" {
		return filepath.Abs(flagVal)
	}
	if v := os.Getenv("CV3_DB"); v != "" {
		return filepath.Abs(v)
	}
	if v := os.Getenv("XDG_DATA_HOME"); v != "" {
		return filepath.Join(v, "cv3", "cv3.db"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate a database: no -db, no CV3_DB and no home directory")
	}
	return filepath.Join(home, ".local", "share", "cv3", "cv3.db"), nil
}

// openReadOnly opens the database for queries, reporting the actionable message
// when it does not exist yet.
func openReadOnly(stderr io.Writer, flagVal string) (*store.DB, int) {
	path, err := resolveDB(flagVal)
	if err != nil {
		return nil, fail(stderr, exitData, "%v", err)
	}
	d, err := store.Open(path, true)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fail(stderr, exitData, "no database at %s; run 'cv3 sync'", path)
		}
		return nil, fail(stderr, exitData, "%v", err)
	}
	return d, exitOK
}

// cweNameMap resolves the names of a record's CWE ids for reporting.
func cweNameMap(d *store.DB, ids []string) (map[string]string, error) {
	if len(ids) == 0 {
		return map[string]string{}, nil
	}
	seen := make(map[string]bool, len(ids))
	unique := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" && !seen[id] {
			seen[id] = true
			unique = append(unique, id)
		}
	}
	return d.CWENames(context.Background(), unique)
}
