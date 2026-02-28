package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	name         = "tcpfwd"
	licenseYear  = "2025"
	licenseOwner = "AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)"
	licenseType  = "CC0-1.0"
)

// replaced by goreleaser / ldflags
var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01"
)

// printVersion displays the version, commit, and build date.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

type forward struct {
	listenAddr string // e.g. ":12345"
	target     string // e.g. "example.com:2345"
}

// parseForward parses a "local-port:remote-host:remote-port" string.
func parseForward(s string) (forward, error) {
	i := strings.Index(s, ":")
	if i < 0 || !strings.Contains(s[i+1:], ":") {
		return forward{}, fmt.Errorf("invalid forward %q: expected local-port:remote-host:remote-port", s)
	}
	return forward{listenAddr: ":" + s[:i], target: s[i+1:]}, nil
}

// connEntry tracks an active proxied connection pair.
type connEntry struct {
	lastRead  atomic.Int64 // UnixNano of last read from either side
	lastWrite atomic.Int64 // UnixNano of last write to either side
	client    net.Conn
	remote    net.Conn
}

// idleSince returns the time of the most recent I/O on this connection.
func (e *connEntry) idleSince() time.Time {
	lr := time.Unix(0, e.lastRead.Load())
	lw := time.Unix(0, e.lastWrite.Load())
	if lr.After(lw) {
		return lr
	}
	return lw
}

func (e *connEntry) isIdle(threshold time.Duration) bool {
	return time.Since(e.idleSince()) > threshold
}

func (e *connEntry) close() {
	e.client.Close()
	e.remote.Close()
}

// connRegistry tracks all active connections.
type connRegistry struct {
	mu    sync.Mutex
	conns map[*connEntry]struct{}
	wg    sync.WaitGroup
}

func newConnRegistry() *connRegistry {
	return &connRegistry{conns: make(map[*connEntry]struct{})}
}

func (r *connRegistry) add(e *connEntry) {
	r.wg.Add(1)
	r.mu.Lock()
	r.conns[e] = struct{}{}
	r.mu.Unlock()
}

func (r *connRegistry) remove(e *connEntry) {
	r.mu.Lock()
	delete(r.conns, e)
	r.mu.Unlock()
	r.wg.Done()
}

// closeIdle closes connections idle for longer than threshold and returns the count.
func (r *connRegistry) closeIdle(threshold time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int
	for e := range r.conns {
		if e.isIdle(threshold) {
			e.close()
			n++
		}
	}
	return n
}

func (r *connRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for e := range r.conns {
		e.close()
	}
}

// trackingConn wraps a net.Conn and updates shared lastRead/lastWrite atomics on I/O.
type trackingConn struct {
	net.Conn
	lastRead  *atomic.Int64
	lastWrite *atomic.Int64
}

func (c *trackingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.lastRead.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *trackingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.lastWrite.Store(time.Now().UnixNano())
	}
	return n, err
}

func main() {
	var listenPort string
	var target string
	var showVersion bool
	var idleTimeout time.Duration
	var shutdownTimeout time.Duration

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&listenPort, "port", "", "local port to listen on (use with --target)")
	fs.StringVar(&target, "target", "", "target host:port (use with --port)")
	fs.BoolVar(&showVersion, "version", false, "show version and exit")
	fs.DurationVar(&idleTimeout, "idle-timeout", 5*time.Second, "close idle connections after this duration on shutdown")
	fs.DurationVar(&shutdownTimeout, "shutdown-timeout", 30*time.Second, "maximum time to wait for active connections to drain on shutdown")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "USAGE\n  %s [flags] [local-port:remote-host:remote-port ...]\n\n", name)
		fmt.Fprintf(os.Stderr, "FLAGS\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nEXAMPLES\n")
		fmt.Fprintf(os.Stderr, "  %s 12345:example.com:2345\n", name)
		fmt.Fprintf(os.Stderr, "  %s 12345:example.com:2345 22222:other.host:22\n", name)
		fmt.Fprintf(os.Stderr, "  %s --port 12345 --target example.com:2345\n", name)
	}

	// Special handling for version/help before full flag parse
	if len(os.Args) > 1 {
		arg := os.Args[1]
		if arg == "-V" || arg == "--version" || arg == "version" {
			printVersion(os.Stdout)
			os.Exit(0)
		}
		if arg == "help" || arg == "-help" || arg == "--help" {
			printVersion(os.Stdout)
			_, _ = fmt.Fprintln(os.Stdout, "")
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	printVersion(os.Stderr)
	fmt.Fprintln(os.Stderr, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		log.Fatalf("flag parse error: %v", err)
	}

	if showVersion {
		printVersion(os.Stdout)
		os.Exit(0)
	}

	// Collect forwards
	var forwards []forward

	// Backward-compat: --port / --target flags
	if target != "" {
		port := listenPort
		if port == "" {
			i := strings.LastIndex(target, ":")
			port = target[i+1:]
		}
		forwards = append(forwards, forward{listenAddr: ":" + port, target: target})
	} else if listenPort != "" {
		fmt.Fprintf(os.Stderr, "error: --port requires --target\n")
		fs.Usage()
		os.Exit(1)
	}

	// Positional args: local-port:remote-host:remote-port
	for _, arg := range fs.Args() {
		fwd, err := parseForward(arg)
		if err != nil {
			log.Fatalf("%v", err)
		}
		forwards = append(forwards, fwd)
	}

	if len(forwards) == 0 {
		fs.Usage()
		os.Exit(1)
	}

	reg := newConnRegistry()

	// Note: allow unprivileged users to use this like so:
	// echo 'net.ipv4.ip_unprivileged_port_start=1' | sudo tee /etc/sysctl.d/01-deprivilege-ports.conf
	// sudo sysctl -p /etc/sysctl.d/01-deprivilege-ports.conf

	// Bind all listeners first (fail fast before starting any accept loops)
	type boundListener struct {
		net.Listener
		target string
	}
	var listeners []boundListener
	for _, fwd := range forwards {
		l, err := net.Listen("tcp", fwd.listenAddr)
		if err != nil {
			log.Fatalf("Failed to bind %s: %v", fwd.listenAddr, err)
		}
		log.Printf("TCP bridge listening on %s → %s", fwd.listenAddr, fwd.target)
		listeners = append(listeners, boundListener{l, fwd.target})
	}

	// Start accept loops
	for _, bl := range listeners {
		go func(bl boundListener) {
			for {
				client, err := bl.Accept()
				if err != nil {
					if isClosedConn(err) {
						return
					}
					log.Printf("Accept error: %v", err)
					continue
				}
				go handleConn(client, bl.target, reg)
			}
		}(bl)
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("Received %s, shutting down...", sig)

	// Stop accepting new connections
	for _, l := range listeners {
		l.Close()
	}

	// Close connections that have been idle longer than idleTimeout
	if n := reg.closeIdle(idleTimeout); n > 0 {
		log.Printf("Closed %d idle connection(s) (idle > %s)", n, idleTimeout)
	}

	// Wait for remaining active connections to drain, up to shutdownTimeout
	drained := make(chan struct{})
	go func() {
		reg.wg.Wait()
		close(drained)
	}()

	select {
	case <-drained:
		log.Printf("All connections closed cleanly")
	case <-time.After(shutdownTimeout):
		log.Printf("Shutdown timeout (%s) exceeded, force-closing remaining connections", shutdownTimeout)
		reg.closeAll()
		reg.wg.Wait()
	}
}

func handleConn(client net.Conn, target string, reg *connRegistry) {
	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", target, err)
		client.Close()
		return
	}

	now := time.Now().UnixNano()
	entry := &connEntry{client: client, remote: remote}
	entry.lastRead.Store(now)
	entry.lastWrite.Store(now)

	reg.add(entry)
	defer reg.remove(entry)
	defer client.Close()
	defer remote.Close()

	log.Printf("New connection %s ↔ %s", client.RemoteAddr(), remote.RemoteAddr())

	trackedClient := &trackingConn{Conn: client, lastRead: &entry.lastRead, lastWrite: &entry.lastWrite}
	trackedRemote := &trackingConn{Conn: remote, lastRead: &entry.lastRead, lastWrite: &entry.lastWrite}

	// Bidirectional copy with error handling
	go func() { _ = copyAndClose(trackedRemote, trackedClient) }()
	_ = copyAndClose(trackedClient, trackedRemote)
}

// copyAndClose copies until EOF or error, then closes dst.
func copyAndClose(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	dst.Close()
	if err != nil && !isClosedConn(err) {
		log.Printf("Copy error (%s → %s): %v",
			src.RemoteAddr(), dst.RemoteAddr(), err)
	}
	return err
}

// isClosedConn detects closed-connection errors.
func isClosedConn(err error) bool {
	return errors.Is(err, net.ErrClosed)
}
