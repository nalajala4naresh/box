package netstack

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CA is box's local interception authority. Its certificate is installed
// in every guest trust store; its key never leaves the host.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreateCA reads dir/ca.pem and dir/ca-key.pem, generating them on
// first use.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return parseCA(certPEM, keyPEM)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "box local interception CA", Organization: []string{"box"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	return parseCA(certPEM, keyPEM)
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, errors.New("malformed box CA files")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key, leaves: map[string]*tls.Certificate{}}, nil
}

// leaf mints (and caches) a server certificate for host.
func (ca *CA) leaf(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cert, ok := ca.leaves[host]; ok && time.Until(cert.Leaf.NotAfter) > time.Hour {
		return cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(0, 0, 30),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key, Leaf: leaf}
	ca.leaves[host] = cert
	return cert, nil
}

var errHelloCaptured = errors.New("client hello captured")

// recordingConn replays nothing and records everything read, so a TLS
// ClientHello can be parsed and then forwarded verbatim.
type recordingConn struct {
	net.Conn
	r   io.Reader
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

// peekClientHello reads the guest's ClientHello without answering it. It
// returns the server name (empty without SNI or for non-TLS traffic) and
// the bytes consumed, which must be replayed to whoever handles the
// connection next.
func peekClientHello(conn net.Conn) (string, []byte, error) {
	rec := &recordingConn{Conn: conn, r: conn}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	var sni string
	err := tls.Server(rec, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni = hello.ServerName
			return nil, errHelloCaptured
		},
	}).Handshake()
	if errors.Is(err, errHelloCaptured) || strings.Contains(fmt.Sprint(err), errHelloCaptured.Error()) {
		return strings.ToLower(sni), rec.buf.Bytes(), nil
	}
	return "", rec.buf.Bytes(), err
}

// prefixConn serves buffered bytes before the live connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func newPrefixConn(conn net.Conn, prefix []byte) *prefixConn {
	return &prefixConn{Conn: conn, r: io.MultiReader(bytes.NewReader(prefix), conn)}
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// secretsFor returns the live secrets scoped to host.
func secretsFor(secrets []Secret, host string) []Secret {
	var out []Secret
	for _, secret := range secrets {
		for _, rule := range secret.Hosts {
			if RuleMatches(rule, host) {
				out = append(out, secret)
				break
			}
		}
	}
	return out
}

// substitute swaps the stand-in for real values in outgoing headers. A
// declared header takes its own secret's value; any other header holding
// the stand-in is filled only when exactly one secret covers the host.
// Basic credentials are decoded so `user:STAND-IN` works too.
func substitute(header http.Header, matching []Secret, placeholder string) {
	if len(matching) == 0 {
		return
	}
	valueFor := func(name string) (string, bool) {
		for _, secret := range matching {
			for _, declared := range secret.Headers {
				if strings.EqualFold(declared, name) {
					return secret.Value, true
				}
			}
		}
		if len(matching) == 1 {
			return matching[0].Value, true
		}
		return "", false
	}
	for name, values := range header {
		for i, value := range values {
			if !strings.Contains(value, placeholder) {
				if strings.EqualFold(name, "Authorization") {
					values[i] = substituteBasic(value, placeholder, func() (string, bool) { return valueFor(name) })
				}
				continue
			}
			if real, ok := valueFor(name); ok {
				values[i] = strings.ReplaceAll(value, placeholder, real)
			}
		}
	}
}

func substituteBasic(value, placeholder string, real func() (string, bool)) string {
	scheme, encoded, ok := strings.Cut(value, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return value
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || !bytes.Contains(decoded, []byte(placeholder)) {
		return value
	}
	secret, ok := real()
	if !ok {
		return value
	}
	replaced := bytes.ReplaceAll(decoded, []byte(placeholder), []byte(secret))
	return scheme + " " + base64.StdEncoding.EncodeToString(replaced)
}

// interceptHTTPS terminates the guest's TLS with a box-minted certificate,
// substitutes secret stand-ins in each request's headers, and relays the
// exchange to the real host over verified TLS.
func (n *Network) interceptHTTPS(guest net.Conn, sni, upstreamAddr string, matching []Secret) {
	defer guest.Close()
	cert, err := n.ca.leaf(sni)
	if err != nil {
		n.log.Warnf("TLS intercept %s: mint certificate: %v", sni, err)
		return
	}
	tlsGuest := tls.Server(guest, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	tlsGuest.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsGuest.Handshake(); err != nil {
		n.log.Debugf("TLS intercept %s: guest handshake: %v", sni, err)
		return
	}
	tlsGuest.SetDeadline(time.Time{})
	raw, err := n.dial("tcp", upstreamAddr)
	if err != nil {
		n.log.Warnf("TLS intercept %s: upstream: %v", sni, err)
		return
	}
	upstream := tls.Client(raw, &tls.Config{
		ServerName: sni,
		NextProtos: []string{"http/1.1"},
		RootCAs:    n.roots,
	})
	defer upstream.Close()
	upstream.SetDeadline(time.Now().Add(30 * time.Second))
	if err := upstream.Handshake(); err != nil {
		n.log.Warnf("TLS intercept %s: upstream handshake: %v", sni, err)
		return
	}
	upstream.SetDeadline(time.Time{})

	guestReader := bufio.NewReader(tlsGuest)
	upstreamReader := bufio.NewReader(upstream)
	for {
		req, err := http.ReadRequest(guestReader)
		if err != nil {
			return
		}
		// Live rotation: re-read the values for every request.
		substitute(req.Header, secretsFor(n.secrets(), sni), n.placeholder)
		if strings.EqualFold(req.Header.Get("Expect"), "100-continue") {
			req.Header.Del("Expect")
			io.WriteString(tlsGuest, "HTTP/1.1 100 Continue\r\n\r\n")
		}
		if err := req.Write(upstream); err != nil {
			return
		}
		var resp *http.Response
		for {
			resp, err = http.ReadResponse(upstreamReader, req)
			if err != nil {
				return
			}
			if resp.StatusCode >= 100 && resp.StatusCode < 200 && resp.StatusCode != http.StatusSwitchingProtocols {
				resp.Write(tlsGuest)
				continue
			}
			break
		}
		if err := resp.Write(tlsGuest); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusSwitchingProtocols {
			splice(newPrefixConn(tlsGuestConn{tlsGuest}, drain(guestReader)), newPrefixConn(upstream, drain(upstreamReader)))
			return
		}
		if req.Close || resp.Close {
			return
		}
	}
}

// tlsGuestConn adapts *tls.Conn to net.Conn for splice.
type tlsGuestConn struct{ *tls.Conn }

func drain(r *bufio.Reader) []byte {
	buffered, _ := r.Peek(r.Buffered())
	return append([]byte(nil), buffered...)
}
