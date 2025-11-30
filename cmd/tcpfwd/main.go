package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"
)

func main() {
	var listenPort string
	var target string
	flag.StringVar(&listenPort, "port", "", "Local port to listen on (same as target by default)")
	flag.StringVar(&target, "target", "", "Target host:port (required)")
	flag.Parse()

	if target == "" {
		flag.Usage()
		os.Exit(1)
	}

	if len(listenPort) == 0 {
		i := strings.LastIndex(target, ":")
		listenPort = target[i+1:]
	}
	listenAddr := ":" + listenPort
	log.Printf("TCP bridge %s → %s", listenAddr, target)

	// Note: allow unprivileged users to use this like so:
	// echo 'net.ipv4.ip_unprivileged_port_start=1' | sudo tee /etc/sysctl.d/01-deprivilege-ports.conf
   // sudo sysctl -p /etc/sysctl.d/01-deprivilege-ports.conf
	listener, err := net.Listen("tcp", listenAddr)

	if err != nil {
		log.Fatalf("Failed to bind %s: %v", listenAddr, err)
	}
	log.Printf("TCP bridge listening on %s → %s", listenAddr, target)

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConn(client, target)
	}
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
