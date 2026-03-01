package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

func (cli *MainConfig) status() {
	if cli.useCSV {
		c := '\t'
		if len(cli.csvComma) > 0 {
			c = rune((cli.csvComma)[0])
		}
		w := csv.NewWriter(os.Stdout)
		w.Comma = c
		_ = w.Write([]string{"type", "name", "next_version", "current_tag", "status"})
		for _, rr := range cli.rows {
			_ = w.Write([]string{rr.releasable, rr.Status, rr.Version, rr.CurrentTag, rr.Path})
		}
		w.Flush()
		return
	}

	headers := []string{ /*"t",*/ "name", "next_version", "current_tag", "status"}
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	// var typeIdx = 0
	var nameIdx = 0
	var versionIdx = 1
	var tagIdx = 2
	var statusIdx = 3
	for _, rr := range cli.rows {
		// colWidths[typeIdx] = 0
		// if len(rr.Type) > colWidths[typeIdx] {
		// 	colWidths[typeIdx] = len(rr.Type)
		// }
		if len(rr.releasable) > colWidths[nameIdx] {
			colWidths[nameIdx] = len(rr.releasable)
		}
		if len(rr.Version) > colWidths[versionIdx] {
			colWidths[versionIdx] = len(rr.Version)
		}
		if len(rr.CurrentTag) > colWidths[tagIdx] {
			colWidths[tagIdx] = len(rr.CurrentTag)
		}
		if len(rr.Status) > colWidths[statusIdx] {
			colWidths[statusIdx] = len(rr.Status)
		}
		// if len(rr.Path) > colWidths[5] {
		// 	colWidths[5] = len(rr.Path)
		// }
	}
	sep := ""
	fmt.Print(sep)
	{
		fmt.Printf("%-*s %s", colWidths[nameIdx], headers[nameIdx], sep)
		fmt.Printf(" %-*s %s", colWidths[versionIdx], headers[versionIdx], sep)
		fmt.Printf(" %-*s %s", colWidths[tagIdx], headers[tagIdx], sep)
		fmt.Printf(" %-*s %s", colWidths[statusIdx], headers[statusIdx], sep)
	}
	fmt.Println()
	fmt.Print(sep)
	for i, w := range colWidths {
		if i == 0 {
			fmt.Printf("%s %s", strings.Repeat("-", w), sep)
			continue
		}
		fmt.Printf(" %s %s", strings.Repeat("-", w), sep)
	}
	fmt.Println()
	for _, rr := range cli.rows {
		fmt.Print(sep)
		// fmt.Printf(" %-*s %s", colWidths[typeIdx], rr.Type, sep)
		fmt.Printf("%-*s %s", colWidths[nameIdx], rr.releasable, sep)
		fmt.Printf(" %-*s %s", colWidths[versionIdx], rr.Version, sep)
		fmt.Printf(" %-*s %s", colWidths[tagIdx], rr.CurrentTag, sep)
		fmt.Printf(" %-*s %s", colWidths[statusIdx], rr.Status, sep)
		// fmt.Printf(" %-*s %s", colWidths[5], rr.Path, sep)
		fmt.Println()
	}
}
