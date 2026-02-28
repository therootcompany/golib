package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
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

func main() {
	var listenPort string
	var target string
	var showVersion bool

	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&listenPort, "port", "", "local port to listen on (use with --target)")
	fs.StringVar(&target, "target", "", "target host:port (use with --port)")
	fs.BoolVar(&showVersion, "version", false, "show version and exit")

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
					log.Printf("Accept error: %v", err)
					continue
				}
				go handleConn(client, bl.target)
			}
		}(bl)
	}

	select {} // block forever
}

func handleConn(client net.Conn, target string) {
	defer client.Close()

	remote, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", target, err)
		return
	}
	defer remote.Close()

	log.Printf("New connection %s ↔ %s", client.RemoteAddr(), remote.RemoteAddr())

	// Bidirectional copy with error handling
	go func() { _ = copyAndClose(remote, client) }()
	func() { _ = copyAndClose(client, remote) }()
}

// copyAndClose copies until EOF or error, then closes dst
func copyAndClose(dst, src net.Conn) error {
	_, err := io.Copy(dst, src)
	dst.Close()
	if err != nil && !isClosedConn(err) {
		log.Printf("Copy error (%s → %s): %v",
			src.RemoteAddr(), dst.RemoteAddr(), err)
	}
	return err
}

// isClosedConn detects common closed-connection errors
func isClosedConn(err error) bool {
	if err == nil {
		return false
	}
	opErr, ok := err.(*net.OpError)
	return ok && opErr.Err.Error() == "use of closed network connection"
}
