package netstack

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// nameTTL is how long an address keeps the names the guest resolved to it.
// Clients cache answers far beyond their TTLs, so this is generous.
const nameTTL = 30 * time.Minute

// dnsCache maps addresses back to the names the guest looked up, so TCP
// connections can be judged by domain.
type dnsCache struct {
	mu   sync.Mutex
	byIP map[netip.Addr]map[string]time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{byIP: map[netip.Addr]map[string]time.Time{}}
}

func (c *dnsCache) record(ip netip.Addr, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := c.byIP[ip]
	if names == nil {
		names = map[string]time.Time{}
		c.byIP[ip] = names
	}
	names[name] = time.Now().Add(nameTTL)
}

func (c *dnsCache) names(ip netip.Addr) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	var out []string
	for name, expiry := range c.byIP[ip] {
		if now.After(expiry) {
			delete(c.byIP[ip], name)
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// upstreamNameservers reads the host's resolv.conf for record types the
// Go resolver cannot answer directly.
func upstreamNameservers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()
	var servers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if addr, err := netip.ParseAddr(fields[1]); err == nil && addr.Is4() {
				servers = append(servers, net.JoinHostPort(fields[1], "53"))
			}
		}
	}
	return servers
}

// serveDNSPacket handles one UDP-style query and returns the reply.
func (n *Network) answerDNS(query []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(query)
	if err != nil {
		return nil
	}
	question, err := parser.Question()
	if err != nil {
		return reply(header, nil, dnsmessage.RCodeFormatError, nil)
	}
	name := question.Name.String()
	host := strings.ToLower(strings.TrimSuffix(name, "."))
	n.log.Debugf("dns query name: Name(%q) type=%s", name, strings.TrimPrefix(question.Type.String(), "Type"))

	policy := n.policy()
	if policy.Denied(host) {
		n.log.Debugf("DNS query denied by network policy domain=%s", host)
		return reply(header, &question, dnsmessage.RCodeRefused, nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	switch question.Type {
	case dnsmessage.TypeA:
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				return reply(header, &question, dnsmessage.RCodeNameError, nil)
			}
			return reply(header, &question, dnsmessage.RCodeServerFailure, nil)
		}
		var answers []dnsmessage.Resource
		for _, addr := range addrs {
			addr = addr.Unmap()
			if !addr.Is4() {
				continue
			}
			n.names.record(addr, host)
			answers = append(answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: addr.As4()},
			})
		}
		return reply(header, &question, dnsmessage.RCodeSuccess, answers)
	case dnsmessage.TypeAAAA:
		// The guest network is IPv4-only.
		return reply(header, &question, dnsmessage.RCodeSuccess, nil)
	}
	if answer := n.forwardDNS(query); answer != nil {
		n.recordAnswers(answer)
		return answer
	}
	return reply(header, &question, dnsmessage.RCodeServerFailure, nil)
}

func (n *Network) forwardDNS(query []byte) []byte {
	for _, server := range n.upstreams {
		conn, err := net.DialTimeout("udp", server, 3*time.Second)
		if err != nil {
			continue
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			continue
		}
		buf := make([]byte, 4096)
		size, err := conn.Read(buf)
		conn.Close()
		if err == nil {
			return buf[:size]
		}
	}
	return nil
}

// recordAnswers remembers A records in forwarded answers (CNAME chains).
func (n *Network) recordAnswers(msg []byte) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(msg); err != nil {
		return
	}
	question, err := parser.Question()
	if err != nil {
		return
	}
	parser.SkipAllQuestions()
	host := strings.ToLower(strings.TrimSuffix(question.Name.String(), "."))
	for {
		header, err := parser.AnswerHeader()
		if err != nil {
			return
		}
		if header.Type != dnsmessage.TypeA {
			parser.SkipAnswer()
			continue
		}
		a, err := parser.AResource()
		if err != nil {
			return
		}
		n.names.record(netip.AddrFrom4(a.A), host)
	}
}

func reply(query dnsmessage.Header, question *dnsmessage.Question, rcode dnsmessage.RCode, answers []dnsmessage.Resource) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 query.ID,
			Response:           true,
			OpCode:             query.OpCode,
			RecursionDesired:   query.RecursionDesired,
			RecursionAvailable: true,
			RCode:              rcode,
		},
		Answers: answers,
	}
	if question != nil {
		msg.Questions = []dnsmessage.Question{*question}
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil
	}
	return packed
}

// serveDNSUDP answers queries on the gateway's UDP port 53.
func (n *Network) serveDNSUDP(conn net.PacketConn) {
	buf := make([]byte, 4096)
	for {
		size, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:size]...)
		go func() {
			if answer := n.answerDNS(query); answer != nil {
				conn.WriteTo(answer, addr)
			}
		}()
	}
}

// serveDNSTCP answers length-prefixed queries on the gateway's TCP port 53.
func (n *Network) serveDNSTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			for {
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				var size [2]byte
				if _, err := io.ReadFull(conn, size[:]); err != nil {
					return
				}
				query := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(conn, query); err != nil {
					return
				}
				answer := n.answerDNS(query)
				if answer == nil {
					return
				}
				var out [2]byte
				binary.BigEndian.PutUint16(out[:], uint16(len(answer)))
				if _, err := conn.Write(append(out[:], answer...)); err != nil {
					return
				}
			}
		}()
	}
}
