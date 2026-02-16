package main

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
)

func peekOption(args []string, flags []string, defaultOpt string) string {
	n := len(args)
	for i := range n {
		if slices.Contains(flags, args[i]) {
			if i+1 < n {
				return args[i+1]
			}
			break
		}
	}

	return defaultOpt
}

func parseEnvs(opts *MainConfig) error {
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			opts.defaultPort = p
		} else {
			return fmt.Errorf("invalid PORT environment variable value: %q", envPort)
		}
	}
	if envAddress := os.Getenv("ADDRESS"); envAddress != "" {
		if _, err := netip.ParseAddr(envAddress); err != nil {
			return fmt.Errorf("invalid ADDRESS environment variable value: %q", envAddress)
		}
		opts.defaultAddress = envAddress
	}

	if opts.pgURL = os.Getenv("PG_URL"); opts.pgURL != "" {
		if _, err := url.Parse(opts.pgURL); err != nil {
			return fmt.Errorf("invalid PG_URL environment variable value: %q", opts.pgURL)
		}
	}
	if opts.jwtInspectURL = os.Getenv("JWT_INSPECT_URL"); opts.jwtInspectURL != "" {
		if _, err := url.Parse(opts.jwtInspectURL); err != nil {
			return fmt.Errorf("invalid JWT_INSPECT_URL environment variable value: %q", opts.jwtInspectURL)
		}
	}

	return nil
}
