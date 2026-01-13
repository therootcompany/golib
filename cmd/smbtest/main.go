package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/hirochachacha/go-smb2"
)

const (
	name         = "smbtest"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal"
	licenseType  = "CC0-1.0"
)

// set by GoReleaser via ldflags
var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01T00:00:00Z"
)

// printVersion displays the version, commit, and build date.
func printVersion() {
	if len(commit) > 7 {
		commit = commit[:7]
	}
	fmt.Fprintf(os.Stderr, "%s v%s %s (%s)\n", name, version, commit, date)
	fmt.Fprintf(os.Stderr, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	fmt.Fprintf(os.Stderr, "Licensed under the %s license\n", licenseType)
}

type CLIConfig struct {
	showVersion bool
	user        string
	host        string
	share       string
	remotePath  string
}

func main() {
	cfg := CLIConfig{}

	mainFlags := flag.NewFlagSet("", flag.ContinueOnError)

	mainFlags.BoolVar(&cfg.showVersion, "version", false, "Print version and exit")
	mainFlags.StringVar(&cfg.user, "user", os.Getenv("SMB_USERNAME"), "ex: 'jon', or set SMB_USERNAME (password will be prompted unless SMB_PASSWORD is set")
	mainFlags.StringVar(&cfg.host, "host", os.Getenv("SMB_HOST"), "ex: 'localhost:445', or set SMB_HOST")
	mainFlags.StringVar(&cfg.share, "share", os.Getenv("SMB_SHARE"), "ex: 'Public', or set SMB_SHARE")
	mainFlags.StringVar(&cfg.remotePath, "remote-path", os.Getenv("SMB_REMOTE_PATH"), "ex: 'Public/goodies.zip', or set SMB_REMOTE_PATH")

	mainFlags.Usage = func() {
		printVersion()
		out := mainFlags.Output()
		_, _ = fmt.Fprintf(out, "\n")
		_, _ = fmt.Fprintf(out, "USAGE\n")
		_, _ = fmt.Fprintf(out, "   smbtest [options] <url>\n")
		mainFlags.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "version", "-version", "--version":
			printVersion()
			return
		case "help", "-help", "--help":
			mainFlags.SetOutput(os.Stdout)
			mainFlags.Usage()
			return
		}
	}

	if err := mainFlags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)

		mainFlags.SetOutput(os.Stderr)
		mainFlags.Usage()
		os.Exit(1)
		return
	}

	// Handle --version flag after parsing
	if cfg.showVersion {
		printVersion()
		return
	}

	pass, hasPass := os.LookupEnv("SMB_PASSWORD")
	if !hasPass {
		fmt.Fprintf(os.Stderr, "SMB_PASSWORD is not set: ")
		fmt.Print("Password: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read password: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\n")
		pass = strings.TrimRight(string(password), "\r\n \t")
	}

	fmt.Printf("%s@%s/%s/%s", cfg.user, cfg.host, cfg.share, cfg.remotePath)
	trySMB(cfg.host, cfg.share, cfg.user, pass, cfg.remotePath)
	fmt.Println("")
}

type SMBClient struct {
	conn    net.Conn
	session *smb2.Session
	fs      *smb2.Share
}

func NewSMBClient(host, share, username, password string) (*SMBClient, error) {
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	f, err := s.Mount(share)
	if err != nil {
		_ = s.Logoff()
		_ = conn.Close()
		return nil, err
	}

	return &SMBClient{conn: conn, session: s, fs: f}, nil
}

func (c *SMBClient) ListFiles(path string) ([]string, error) {
	matches, err := fs.Glob(c.fs.DirFS(path), "*")
	if err != nil {
		return nil, err
	}
	return matches, nil
}

func (c *SMBClient) ReceiveFile(path string, w io.Writer) error {
	f, err := c.fs.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	_, err = io.Copy(w, f)
	return err
}

func (c *SMBClient) Close() {
	_ = c.fs.Umount()
	_ = c.session.Logoff()
	_ = c.conn.Close()
}

func trySMB(host, share, username, password, rpath string) {
	client, err := NewSMBClient(host, share, username, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return
	}
	defer client.Close()

	// List files
	files, err := client.ListFiles(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "List error: %v\n", err)
		return
	}
	if len(files) == 0 {
		fmt.Println("No files")
	}
	for _, f := range files {
		fmt.Println("   ", f)
	}

	// Receive file
	f, err := os.Create(rpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Create error: %v\n", err)
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Close error: %v\n", err)
		}
	}()

	err = client.ReceiveFile(rpath, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Receive error: %v\n", err)
	}
}
