package netstack

import (
	"net/netip"
	"strings"
)

// Policy is the egress policy one VM's network enforces.
type Policy struct {
	// Public allows everything routable on the public internet and nothing
	// private: the profile build VMs use.
	Public bool `json:"public,omitempty"`
	// AllowEverything opens egress except for explicit Deny matches.
	AllowEverything bool `json:"allow_everything,omitempty"`
	// Allow lists hosts reachable on ports 80 and 443: exact names, or a
	// leading `.` / `*.` for an apex plus subdomains.
	Allow []string `json:"allow,omitempty"`
	// Deny uses the same grammar and beats Allow.
	Deny []string `json:"deny,omitempty"`
}

// allowedPorts are the only destinations domain allow rules open.
var allowedPorts = map[uint16]bool{80: true, 443: true}

// httpsPort is where SNI checks and secret interception apply.
var httpsPort uint16 = 443

// RuleMatches checks one allow/deny entry against a host. Exact entries
// match only themselves; a leading `.` or `*.` covers the apex plus all
// subdomains.
func RuleMatches(rule, host string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	apex, ok := strings.CutPrefix(rule, "*.")
	if !ok {
		apex, ok = strings.CutPrefix(rule, ".")
	}
	if ok {
		return host == apex || strings.HasSuffix(host, "."+apex)
	}
	return host == rule
}

func matchesAny(rules []string, host string) bool {
	for _, rule := range rules {
		if RuleMatches(rule, host) {
			return true
		}
	}
	return false
}

// Denied reports whether an explicit deny rule covers host.
func (p Policy) Denied(host string) bool { return matchesAny(p.Deny, host) }

// Reachable reports whether host may be contacted on an allowed port.
func (p Policy) Reachable(host string) bool {
	if p.Denied(host) {
		return false
	}
	if p.Public || p.AllowEverything {
		return true
	}
	return matchesAny(p.Allow, host)
}

// verdict is the outcome of a connection decision.
type verdict int

const (
	allow verdict = iota
	// denyExplicit is a deny rule match: logged as a policy denial.
	denyExplicit
	// denyDefault is a default-deny refusal: logged quietly.
	denyDefault
)

// decideTCP judges a guest connection by destination address, port, and
// the names the guest resolved to that address.
func (p Policy) decideTCP(dst netip.Addr, port uint16, names []string) (verdict, string) {
	for _, name := range names {
		if p.Denied(name) {
			return denyExplicit, name
		}
	}
	if p.Public {
		if !isPublic(dst) {
			return denyExplicit, dst.String()
		}
		return allow, ""
	}
	if p.AllowEverything {
		return allow, ""
	}
	if !allowedPorts[port] {
		return denyDefault, ""
	}
	for _, name := range names {
		if matchesAny(p.Allow, name) {
			return allow, name
		}
	}
	return denyDefault, ""
}

// decideUDP judges non-DNS UDP. Only open policies forward it.
func (p Policy) decideUDP(dst netip.Addr, names []string) verdict {
	for _, name := range names {
		if p.Denied(name) {
			return denyExplicit
		}
	}
	switch {
	case p.Public && isPublic(dst):
		return allow
	case p.AllowEverything:
		return allow
	}
	return denyDefault
}

var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

func isPublic(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
