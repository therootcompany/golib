# [ipcohort](https://github.com/therootcompany/golib/tree/main/net/ipcohort)

A memory-efficient, fast IP cohort checker for blacklists, whitelists, and ad cohorts.

- 6 bytes per IP address (5 + 1 for alignment)
- binary search (not as fast as a trie, but memory is linear)
- atomic swaps for updates

## Example

Check if an IP address belongs to a cohort (such as a blacklist):

```go
func main() {
    ipStr := "92.255.85.72"

    path := "/opt/github.com/bitwire-it/ipblocklist/inbound.txt"
    unsorted := false

	blacklist, err := ipcohort.LoadFile(path, unsorted)
	if err != nil {
		log.Fatalf("Failed to load blacklist: %v", err)
	}

	if blacklist.Contains(ipStr) {
		fmt.Printf("%s is BLOCKED\n", ipStr)
		os.Exit(1)
	}

	fmt.Printf("%s is allowed\n", ipStr)
}
```

Update the list periodically:

```go
func backgroundUpdate(path string, c *ipcohort.Cohort) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		needsSort := false
		nextCohort, err := ipcohort.LoadFile(path, needsSort)
		if err != nil {
			log.Printf("reload failed: %v", err)
			continue
		}

		log.Printf("reloaded %d blacklist entries", c.Size())
		c.Swap(nextCohort)
	}
}
```
