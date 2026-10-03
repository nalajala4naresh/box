package netstack

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// guest is a second gVisor stack standing in for the VM's kernel on the
// other end of the frame socket.
type guest struct {
	stack *stack.Stack
	link  *channel.Endpoint
}

func newGuest(t *testing.T, fd int) *guest {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(1024, MTU, tcpip.LinkAddress(GuestMAC[:]))
	if err := s.CreateNIC(1, ethernet.New(link)); err != nil {
		t.Fatal(err)
	}
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(GuestIP.As4()), PrefixLen: 24},
	}, stack.AddressProperties{})
	any4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	s.SetRouteTable([]tcpip.Route{{Destination: any4, Gateway: tcpip.AddrFrom4(GatewayIP.As4()), NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); link.Close(); s.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			size, err := unix.Read(fd, buf)
			if err != nil {
				return
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), buf[:size]...))})
			link.InjectInbound(0, pkt)
			pkt.DecRef()
		}
	}()
	go func() {
		for {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			unix.Write(fd, view.AsSlice())
			view.Release()
			pkt.DecRef()
		}
	}()
	return &guest{stack: s, link: link}
}

func (g *guest) dial(t *testing.T, addr netip.AddrPort) (net.Conn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return gonet.DialContextTCP(ctx, g.stack, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(addr.Addr().As4()), Port: addr.Port()}, ipv4.ProtocolNumber)
}

func (g *guest) lookup(t *testing.T, name string) (dnsmessage.RCode, []netip.Addr) {
	t.Helper()
	conn, err := gonet.DialUDP(g.stack, nil, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4(GatewayIP.As4()), Port: 53}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	query := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}
	packed, _ := query.Pack()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(packed); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	size, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("dns read: %v", err)
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(buf[:size]); err != nil {
		t.Fatal(err)
	}
	var addrs []netip.Addr
	for _, answer := range msg.Answers {
		if a, ok := answer.Body.(*dnsmessage.AResource); ok {
			addrs = append(addrs, netip.AddrFrom4(a.A))
		}
	}
	return msg.RCode, addrs
}

type harness struct {
	net   *Network
	guest *guest
	log   *bytes.Buffer
}

type syncBuffer struct {
	bytes.Buffer
}

// fakeUpstream is a public-looking address the test dialer maps to the
// host loopback; the guest stack would drop loopback destinations.
var fakeUpstream = netip.MustParseAddr("203.0.113.10")

func start(t *testing.T, cfg Config) *harness {
	t.Helper()
	cfg.Dial = func(network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		if host == fakeUpstream.String() {
			addr = net.JoinHostPort("127.0.0.1", port)
		}
		return net.DialTimeout(network, addr, 5*time.Second)
	}
	vmEnd, netEnd, err := SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(vmEnd); unix.Close(netEnd) })
	logBuf := &bytes.Buffer{}
	cfg.Log = NewLogger(logBuf)
	cfg.Placeholder = "NOT-AN-ACTUAL-KEY"
	n, err := New(cfg, netEnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.Close)
	return &harness{net: n, guest: newGuest(t, vmEnd), log: logBuf}
}

func (h *harness) logged() string {
	h.net.log.mu.Lock()
	defer h.net.log.mu.Unlock()
	return h.log.String()
}

func echoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(conn, conn); conn.Close() }()
		}
	}()
	return netip.AddrPortFrom(fakeUpstream, uint16(ln.Addr().(*net.TCPAddr).Port))
}

func roundTrip(t *testing.T, conn net.Conn) error {
	t.Helper()
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		return err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if line != "ping\n" {
		return fmt.Errorf("echo returned %q", line)
	}
	return nil
}

func allowPort(t *testing.T, port uint16) {
	allowedPorts[port] = true
	t.Cleanup(func() { delete(allowedPorts, port) })
}

func TestDNSResolvesAndRefusesDeniedNames(t *testing.T) {
	h := start(t, Config{Policy: Policy{Allow: []string{"localhost"}, Deny: []string{".blocked.test"}}})
	rcode, addrs := h.guest.lookup(t, "localhost.")
	if rcode != dnsmessage.RCodeSuccess || len(addrs) == 0 || addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("localhost: %v %v", rcode, addrs)
	}
	if rcode, _ := h.guest.lookup(t, "ads.blocked.test."); rcode != dnsmessage.RCodeRefused {
		t.Fatalf("denied name: %v", rcode)
	}
	log := h.logged()
	if !strings.Contains(log, `Name("localhost.")`) || !strings.Contains(log, "DNS query denied by network policy domain=ads.blocked.test") {
		t.Fatal(log)
	}
}

func TestTCPFollowsResolvedNamesAndPorts(t *testing.T) {
	echo := echoServer(t)
	h := start(t, Config{Policy: Policy{Allow: []string{"localhost"}}})

	// Not an allowed port, and no name: refused.
	if conn, err := h.guest.dial(t, echo); err == nil {
		if roundTrip(t, conn) == nil {
			t.Fatal("unresolved destination must be refused")
		}
	}
	allowPort(t, echo.Port())
	// Allowed port, but the guest never resolved a name for the address.
	if conn, err := h.guest.dial(t, echo); err == nil {
		if roundTrip(t, conn) == nil {
			t.Fatal("address without an allowed name must be refused")
		}
	}
	if !strings.Contains(h.logged(), "TCP egress refused (default deny)") {
		t.Fatal(h.logged())
	}
	// Once the guest resolves an allowed name to it, the address opens.
	h.net.names.record(fakeUpstream, "localhost")
	conn, err := h.guest.dial(t, echo)
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(t, conn); err != nil {
		t.Fatal(err)
	}
}

func TestDenyBeatsAllowEverything(t *testing.T) {
	echo := echoServer(t)
	h := start(t, Config{Policy: Policy{AllowEverything: true}})
	conn, err := h.guest.dial(t, echo)
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(t, conn); err != nil {
		t.Fatalf("allow-everything must connect: %v", err)
	}
	h.net.SetPolicy(Policy{AllowEverything: true, Deny: []string{"localhost"}})
	h.net.names.record(echo.Addr(), "localhost")
	if conn, err := h.guest.dial(t, echo); err == nil && roundTrip(t, conn) == nil {
		t.Fatal("denied name must be refused")
	}
	if !strings.Contains(h.logged(), "TCP egress denied by domain policy") {
		t.Fatal(h.logged())
	}
}

func TestPublicProfileRejectsPrivateAddresses(t *testing.T) {
	echo := echoServer(t)
	h := start(t, Config{Policy: Policy{Public: true}})
	conn, err := h.guest.dial(t, echo)
	if err != nil || roundTrip(t, conn) != nil {
		t.Fatalf("public address must connect: %v", err)
	}
	private := netip.AddrPortFrom(netip.MustParseAddr("10.1.2.3"), echo.Port())
	if conn, err := h.guest.dial(t, private); err == nil && roundTrip(t, conn) == nil {
		t.Fatal("private address must be refused")
	}
}

func TestInterceptsHTTPSAndSubstitutesSecrets(t *testing.T) {
	var seen []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization")+"|"+r.Header.Get("X-Other"))
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "hello %s", r.URL.Path)
	}))
	t.Cleanup(server.Close)
	addr := netip.AddrPortFrom(fakeUpstream, uint16(server.Listener.Addr().(*net.TCPAddr).Port))
	oldHTTPS := httpsPort
	httpsPort = addr.Port()
	t.Cleanup(func() { httpsPort = oldHTTPS })
	allowPort(t, addr.Port())

	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	h := start(t, Config{
		Policy:        Policy{Allow: []string{"localhost", "example.com"}},
		CA:            ca,
		UpstreamRoots: roots,
		Secrets:       []Secret{{Env: "TOKEN", Value: "real-secret", Hosts: []string{"example.com"}, Headers: []string{"Authorization"}}},
	})
	h.net.names.record(fakeUpstream, "localhost")

	guestRoots := x509.NewCertPool()
	guestRoots.AddCert(ca.Cert)
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return h.guest.dial(t, addr)
		},
		TLSClientConfig: &tls.Config{RootCAs: guestRoots, ServerName: "example.com"},
	}}
	for _, path := range []string{"/one", "/two"} {
		req, _ := http.NewRequest("GET", "https://example.com:"+strconv.Itoa(int(addr.Port()))+path, nil)
		req.Header.Set("Authorization", "Bearer NOT-AN-ACTUAL-KEY")
		req.Header.Set("X-Other", "NOT-AN-ACTUAL-KEY")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v\n%s", path, err, h.logged())
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(body) != "hello "+path {
			t.Fatalf("body %q", body)
		}
	}
	// One secret covers the host, so even an undeclared header is filled.
	for _, got := range seen {
		if got != "Bearer real-secret|real-secret" {
			t.Fatalf("upstream saw %q", got)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("requests %v", seen)
	}

	// Rotation applies to the next connection without a restart.
	h.net.SetSecrets([]Secret{{Env: "TOKEN", Value: "rotated", Hosts: []string{"example.com"}, Headers: []string{"Authorization"}}})
	client.CloseIdleConnections()
	req, _ := http.NewRequest("GET", "https://example.com:"+strconv.Itoa(int(addr.Port()))+"/three", nil)
	req.Header.Set("Authorization", "Bearer NOT-AN-ACTUAL-KEY")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen[len(seen)-1] != "Bearer rotated|" {
		t.Fatalf("rotated value not used: %q", seen[len(seen)-1])
	}
}

func TestSNIMustBeAllowed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(server.Close)
	addr := netip.AddrPortFrom(fakeUpstream, uint16(server.Listener.Addr().(*net.TCPAddr).Port))
	oldHTTPS := httpsPort
	httpsPort = addr.Port()
	t.Cleanup(func() { httpsPort = oldHTTPS })
	allowPort(t, addr.Port())
	h := start(t, Config{Policy: Policy{Allow: []string{"localhost"}}})
	h.net.names.record(fakeUpstream, "localhost")
	conn, err := h.guest.dial(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(conn, &tls.Config{ServerName: "evil.test", InsecureSkipVerify: true})
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if err := client.Handshake(); err == nil {
		t.Fatal("SNI outside the allowlist must be cut off")
	}
	if !strings.Contains(h.logged(), "TLS SNI did not match CONNECT authority sni=evil.test") {
		t.Fatal(h.logged())
	}
}

func TestPublishedPortsReachTheGuest(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	hostPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close()
	h := start(t, Config{Policy: Policy{}, Ports: []PortForward{{Host: hostPort, Guest: 8080}}})
	guestLn, err := gonet.ListenTCP(h.guest.stack, tcpip.FullAddress{NIC: 1, Port: 8080}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { guestLn.Close() })
	go func() {
		conn, err := guestLn.Accept()
		if err == nil {
			io.Copy(conn, conn)
			conn.Close()
		}
	}()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(hostPort))), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := roundTrip(t, conn); err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestSubstituteBasicCredentials(t *testing.T) {
	header := http.Header{}
	header.Set("Authorization", "Basic eC1hY2Nlc3MtdG9rZW46Tk9ULUFOLUFDVFVBTC1LRVk=") // x-access-token:NOT-AN-ACTUAL-KEY
	substitute(header, []Secret{{Value: "tok", Headers: []string{"Authorization"}}}, "NOT-AN-ACTUAL-KEY")
	if header.Get("Authorization") != "Basic eC1hY2Nlc3MtdG9rZW46dG9r" {
		t.Fatal(header.Get("Authorization"))
	}
}

func TestAmbiguousUndeclaredHeaderStaysPlaceholder(t *testing.T) {
	header := http.Header{}
	header.Set("X-Thing", "NOT-AN-ACTUAL-KEY")
	header.Set("X-Api-Key", "NOT-AN-ACTUAL-KEY")
	substitute(header, []Secret{
		{Value: "a", Headers: []string{"X-Api-Key"}},
		{Value: "b", Headers: []string{"Authorization"}},
	}, "NOT-AN-ACTUAL-KEY")
	if header.Get("X-Api-Key") != "a" || header.Get("X-Thing") != "NOT-AN-ACTUAL-KEY" {
		t.Fatal(header)
	}
}
