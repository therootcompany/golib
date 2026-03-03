package main

import (
	"slices"
	"strings"
)

func ArgFields(list string, optionalDelim string, nothings []string) (args []string) {
	list = strings.ReplaceAll(list, optionalDelim, " ")
	list = strings.TrimSpace(list)
	if list == "" || slices.Contains(nothings, list) {
		return nil
	}

	args = strings.Fields(list)
	if len(args) == 1 && args[0] == "" {
		return nil
	}

	return args
}
