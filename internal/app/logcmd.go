package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/nalajala4naresh/box/internal/config"
	"github.com/nalajala4naresh/box/internal/sandbox"
	"github.com/nalajala4naresh/box/internal/store"
)

// runLog surfaces the guest's blocked network requests without booting a
// VM, from this workspace's session diagnostics. Two signals: explicit
// policy denials the network logs (DNS refusals, TCP/TLS denied by domain
// policy, SNI mismatches), and guest DNS lookups for names the effective
// policy leaves unreachable (covers the quiet default-deny refusals).
func runLog(cwd, explicit string, tail int, follow bool) (int, error) {
	name, err := SandboxName(cwd)
	if err != nil {
		return 1, err
	}
	missing := fmt.Errorf("no box session for %s", cwd)
	st, err := store.OpenExisting()
	if err != nil {
		return 1, missing
	}
	sb, err := sandbox.Get(st, name)
	if err != nil {
		return 1, missing
	}
	// Reachability judging needs the resolved secrets, but a broken secret
	// setup must not block reading the raw denials.
	var policy *logPolicy
	if loaded, err := config.LoadFull(cwd, explicit); err == nil {
		if secrets, err := config.ResolveSecrets(loaded.Config); err == nil {
			policy = &logPolicy{cfg: loaded.Config, secrets: secrets}
		}
	}
	shown := map[string]bool{}
	if follow {
		seen := 0
		for {
			entries, err := sb.Logs()
			if err != nil {
				return 1, err
			}
			seen, _ = printNewLogHits(entries, policy, seen, shown, int(^uint(0)>>1))
			time.Sleep(time.Second)
		}
	}
	entries, err := sb.Logs()
	if err != nil {
		return 1, err
	}
	if _, printed := printNewLogHits(entries, policy, 0, shown, tail); printed == 0 {
		fmt.Printf("no denied requests in %s's logs\n", name)
	}
	return 0, nil
}

type logPolicy struct {
	cfg     config.Config
	secrets config.ResolvedSecrets
}

// printNewLogHits prints denial lines and unreachable lookups in
// entries[seen:]. Denials print newest-last capped at tail; each
// unreachable name prints once, on first sight.
func printNewLogHits(entries []sandbox.LogEntry, policy *logPolicy, seen int, shown map[string]bool, tail int) (int, int) {
	if seen > len(entries) {
		seen = len(entries)
	}
	fresh := entries[seen:]
	var denied []sandbox.LogEntry
	for _, entry := range fresh {
		if isDenialLine(entry.Body) {
			denied = append(denied, entry)
		}
	}
	start := max(len(denied)-tail, 0)
	printed := 0
	for _, entry := range denied[start:] {
		fmt.Printf("%s %s\n", entry.Timestamp, strings.TrimSpace(entry.Body))
		printed++
	}
	if policy != nil {
		unreachable := map[string]bool{}
		for _, entry := range fresh {
			for _, name := range dnsLookupNames(entry.Body) {
				if !config.IsHostReachable(policy.cfg, policy.secrets, name) {
					unreachable[name] = true
				}
			}
		}
		names := make([]string, 0, len(unreachable))
		for name := range unreachable {
			if !shown[name] {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Printf("looked up but unreachable: %s\n", name)
			shown[name] = true
			printed++
		}
	}
	return len(entries), printed
}

// dnsLookupNames extracts guest DNS lookups from a diagnostics line:
// query lines (`Name("example.com.")`) and dig-style question echoes
// (`;; example.com. IN A`). Lowercased, undotted, in first-seen order.
func dnsLookupNames(body string) []string {
	var names []string
	rest := body
	for {
		start := strings.Index(rest, `Name("`)
		if start < 0 {
			break
		}
		rest = rest[start+6:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			break
		}
		names = pushLookupName(names, rest[:end])
		rest = rest[end+1:]
	}
	for _, line := range strings.Split(body, "\n") {
		if question, ok := strings.CutPrefix(strings.TrimSpace(line), ";;"); ok {
			if fields := strings.Fields(question); len(fields) >= 3 {
				names = pushLookupName(names, fields[0])
			}
		}
	}
	return names
}

func pushLookupName(names []string, raw string) []string {
	name := strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "."))
	if !strings.Contains(name, ".") {
		return names
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return names
		}
	}
	for _, existing := range names {
		if existing == name {
			return names
		}
	}
	return append(names, name)
}

// isDenialLine matches the explicit denials the network logs: DNS lookups
// refused by policy, TCP/TLS egress refused by a deny rule, and TLS
// handshakes cut off on an SNI outside the allowlist.
func isDenialLine(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "denied by domain policy") ||
		strings.Contains(lower, "denied by network policy") ||
		strings.Contains(lower, "did not match connect authority")
}
