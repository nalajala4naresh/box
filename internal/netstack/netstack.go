// Package netstack is the userspace network behind every wrap VM. libkrun
// hands it raw Ethernet frames over a datagram socket (virtio-net with a
// unixgram backend); a gVisor TCP/IP stack terminates them, so every guest
// connection is a host-side decision:
//
//   - DNS goes only to the gateway, which resolves on the host, refuses
//     explicitly denied names, and remembers which names map to which
//     addresses.
//   - TCP is judged by destination port and the names the guest resolved to
//     the destination address; port 443 is additionally checked against
//     the TLS SNI.
//   - HTTPS to hosts with live secrets is intercepted so the guest-visible
//     stand-in can be replaced by the real credential on the wire.
//   - Published ports forward host loopback listeners into the guest.
package netstack

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Fixed guest addressing. Every VM gets its own stack, so they never clash.
var (
	GatewayIP  = netip.MustParseAddr("192.168.127.1")
	GuestIP    = netip.MustParseAddr("192.168.127.2")
	GuestCIDR  = "192.168.127.2/24"
	GatewayMAC = net.HardwareAddr{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xdd}
	GuestMAC   = [6]byte{0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xee}
)

// MTU of the guest link. No offloads are negotiated, so frames stay small.
const MTU = 1500

const nicID tcpip.NICID = 1

// Secret is one live credential the network substitutes on the wire.
type Secret struct {
	Env     string   `json:"env"`
	Value   string   `json:"value"`
	Hosts   []string `json:"hosts"`
	Headers []string `json:"headers"`
}

// PortForward publishes a guest TCP port on the host loopback.
type PortForward struct {
	Host  uint16 `json:"host"`
	Guest uint16 `json:"guest"`
}

// Config configures one VM's network.
type Config struct {
	Policy      Policy
	Secrets     []Secret
	Ports       []PortForward
	CA          *CA
	Placeholder string
	Log         *Logger
	// UpstreamRoots overrides the system roots for intercepted upstreams
	// (tests only).
	UpstreamRoots *x509.CertPool
	// Dial overrides how upstream TCP connections are made (tests only).
	Dial func(network, addr string) (net.Conn, error)
}

// Network is a running userspace network.
type Network struct {
	stack       *stack.Stack
	link        *channel.Endpoint
	fd          int
	ca          *CA
	placeholder string
	log         *Logger
	names       *dnsCache
	upstreams   []string
	roots       *x509.CertPool
	dial        func(network, addr string) (net.Conn, error)

	policyV  atomic.Pointer[Policy]
	secretsV atomic.Pointer[[]Secret]

	ctx       context.Context
	cancel    context.CancelFunc
	listeners []net.Listener
	closeOnce sync.Once
}

// SocketPair returns a datagram socket pair sized for Ethernet frames: one
// end for libkrun, one for New.
func SocketPair() (vmEnd, netEnd int, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return -1, -1, err
	}
	for _, fd := range fds {
		// On macOS the send buffer caps the datagram size.
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
		unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	}
	return fds[0], fds[1], nil
}

// New starts a network on fd, the host end of a SocketPair.
func New(cfg Config, fd int) (*Network, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	link := channel.New(1024, MTU, tcpip.LinkAddress(GatewayMAC))
	if err := s.CreateNIC(nicID, ethernet.New(link)); err != nil {
		return nil, fmt.Errorf("create nic: %s", err)
	}
	gateway := tcpip.AddrFrom4(GatewayIP.As4())
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: gateway, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add gateway address: %s", err)
	}
	// Accept traffic for every destination: the gateway impersonates the
	// whole internet and decides per connection.
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	any4, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	s.SetRouteTable([]tcpip.Route{{Destination: any4, NIC: nicID}})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	ctx, cancel := context.WithCancel(context.Background())
	n := &Network{
		stack:       s,
		link:        link,
		fd:          fd,
		ca:          cfg.CA,
		placeholder: cfg.Placeholder,
		log:         cfg.Log,
		names:       newDNSCache(),
		upstreams:   upstreamNameservers(),
		roots:       cfg.UpstreamRoots,
		dial:        cfg.Dial,
		ctx:         ctx,
		cancel:      cancel,
	}
	if n.dial == nil {
		n.dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 15*time.Second)
		}
	}
	n.SetPolicy(cfg.Policy)
	n.SetSecrets(cfg.Secrets)

	tcpForwarder := tcp.NewForwarder(s, 0, 4096, n.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(s, n.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	dnsAddr := tcpip.FullAddress{NIC: nicID, Addr: gateway, Port: 53}
	dnsUDP, err := gonet.DialUDP(s, &dnsAddr, nil, ipv4.ProtocolNumber)
	if err != nil {
		n.Close()
		return nil, fmt.Errorf("dns udp: %w", err)
	}
	dnsTCP, err := gonet.ListenTCP(s, dnsAddr, ipv4.ProtocolNumber)
	if err != nil {
		n.Close()
		return nil, fmt.Errorf("dns tcp: %w", err)
	}
	n.listeners = append(n.listeners, dnsTCP)
	go n.serveDNSUDP(dnsUDP)
	go n.serveDNSTCP(dnsTCP)

	for _, port := range cfg.Ports {
		ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port.Host))))
		if err != nil {
			n.Close()
			return nil, fmt.Errorf("publish port %d: %w", port.Host, err)
		}
		n.listeners = append(n.listeners, ln)
		go n.forwardPort(ln, port.Guest)
	}

	go n.readFrames()
	go n.writeFrames()
	return n, nil
}

func (n *Network) policy() Policy { return *n.policyV.Load() }

func (n *Network) secrets() []Secret { return *n.secretsV.Load() }

// SetPolicy swaps the egress policy for new connections.
func (n *Network) SetPolicy(p Policy) { n.policyV.Store(&p) }

// SetSecrets rotates credential values live.
func (n *Network) SetSecrets(secrets []Secret) {
	copied := append([]Secret(nil), secrets...)
	n.secretsV.Store(&copied)
}

// Close stops the network.
func (n *Network) Close() {
	n.closeOnce.Do(func() {
		n.cancel()
		for _, ln := range n.listeners {
			ln.Close()
		}
		n.link.Close()
		n.stack.Close()
	})
}

// readFrames moves guest frames into the stack.
func (n *Network) readFrames() {
	buf := make([]byte, 65536)
	for {
		size, err := unix.Read(n.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
				continue
			}
			n.Close()
			return
		}
		if size == 0 {
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), buf[:size]...)),
		})
		n.link.InjectInbound(0, pkt)
		pkt.DecRef()
	}
}

// writeFrames moves stack frames to the guest.
func (n *Network) writeFrames() {
	for {
		pkt := n.link.ReadContext(n.ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		frame := view.AsSlice()
		for {
			_, err := unix.Write(n.fd, frame)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.EAGAIN) {
				time.Sleep(time.Millisecond)
				continue
			}
			break
		}
		view.Release()
		pkt.DecRef()
	}
}

func addrOf(a tcpip.Address) netip.Addr {
	b := a.As4()
	return netip.AddrFrom4(b)
}

func (n *Network) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := addrOf(id.LocalAddress)
	port := id.LocalPort
	if dst == GatewayIP {
		// Only DNS lives on the gateway, and it has its own listener.
		r.Complete(true)
		return
	}
	names := n.names.names(dst)
	target := net.JoinHostPort(dst.String(), strconv.Itoa(int(port)))
	policy := n.policy()
	switch verdict, why := policy.decideTCP(dst, port, names); verdict {
	case denyExplicit:
		n.log.Debugf("TCP egress denied by domain policy dst=%s host=%s", target, why)
		r.Complete(true)
		return
	case denyDefault:
		n.log.Debugf("TCP egress refused (default deny) dst=%s names=%v", target, names)
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		r.Complete(true)
		return
	}
	r.Complete(false)
	guest := gonet.NewTCPConn(&wq, ep)
	go n.proxyTCP(guest, dst, port, target, policy)
}

func (n *Network) proxyTCP(guest net.Conn, dst netip.Addr, port uint16, target string, policy Policy) {
	var prefix []byte
	if port == httpsPort {
		sni, consumed, err := peekClientHello(guest)
		prefix = consumed
		if err == nil && sni != "" {
			// A domain-scoped allow must match the name the client asks the
			// server for, not just an address that name shares.
			if !policy.Public && !policy.AllowEverything && !policy.Reachable(sni) {
				n.log.Debugf("TLS SNI did not match CONNECT authority sni=%s dst=%s", sni, target)
				guest.Close()
				return
			}
			if policy.Denied(sni) {
				n.log.Debugf("TLS egress denied by domain policy sni=%s dst=%s", sni, target)
				guest.Close()
				return
			}
			if matching := secretsFor(n.secrets(), sni); len(matching) > 0 && n.ca != nil {
				n.interceptHTTPS(newPrefixConn(guest, prefix), sni, target, matching)
				return
			}
		}
	}
	upstream, err := n.dial("tcp", target)
	if err != nil {
		n.log.Debugf("TCP egress dial %s: %v", target, err)
		guest.Close()
		return
	}
	splice(newPrefixConn(guest, prefix), upstream)
}

// splice copies both directions until either side finishes, then closes
// both.
func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	copyHalf := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	wg.Add(2)
	go copyHalf(a, b)
	go copyHalf(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}

func (n *Network) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dst := addrOf(id.LocalAddress)
	if dst == GatewayIP {
		return false
	}
	target := net.JoinHostPort(dst.String(), strconv.Itoa(int(id.LocalPort)))
	names := n.names.names(dst)
	switch n.policy().decideUDP(dst, names) {
	case denyExplicit:
		n.log.Debugf("UDP egress denied by domain policy dst=%s", target)
		return true
	case denyDefault:
		n.log.Debugf("UDP egress refused (default deny) dst=%s", target)
		return true
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	guest := gonet.NewUDPConn(&wq, ep)
	go n.relayUDP(guest, target)
	return true
}

func (n *Network) relayUDP(guest *gonet.UDPConn, target string) {
	defer guest.Close()
	upstream, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer upstream.Close()
	const idle = 60 * time.Second
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65536)
		for {
			upstream.SetReadDeadline(time.Now().Add(idle))
			size, err := upstream.Read(buf)
			if err != nil {
				return
			}
			if _, err := guest.Write(buf[:size]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65536)
	for {
		guest.SetReadDeadline(time.Now().Add(idle))
		size, err := guest.Read(buf)
		if err != nil {
			break
		}
		if _, err := upstream.Write(buf[:size]); err != nil {
			break
		}
	}
	upstream.Close()
	<-done
}

// forwardPort publishes a guest port on a host loopback listener.
func (n *Network) forwardPort(ln net.Listener, guestPort uint16) {
	for {
		host, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(n.ctx, 10*time.Second)
			defer cancel()
			guest, err := gonet.DialContextTCP(ctx, n.stack, tcpip.FullAddress{
				NIC:  nicID,
				Addr: tcpip.AddrFrom4(GuestIP.As4()),
				Port: guestPort,
			}, ipv4.ProtocolNumber)
			if err != nil {
				host.Close()
				return
			}
			splice(host, guest)
		}()
	}
}
