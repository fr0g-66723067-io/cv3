package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fr0g-66723067-io/cv3/internal/api"
)

func runServe(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("serve")
	db := fs.String("db", "", "database path")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")

	flags, _ := splitArgs(fs, args)
	if status, ok := parseFlags(fs, flags, stdout, stderr); !ok {
		return status
	}
	d, code := openReadOnly(stderr, *db)
	if code != exitOK {
		return code
	}
	defer d.Close()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fail(stderr, exitData, "listen %s: %v", *addr, err)
	}
	srv := &http.Server{
		Handler:           api.New(d, stderr),
		ReadHeaderTimeout: 5 * time.Second,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		<-ctx.Done()
		fmt.Fprintln(stderr, "cv3: shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(stderr, "cv3: shutdown: %v\n", err)
		}
	}()

	fmt.Fprintf(stderr, "cv3: serving %s on http://%s\n", d.Path(), ln.Addr())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail(stderr, exitData, "serve: %v", err)
	}
	<-done
	return exitOK
}
