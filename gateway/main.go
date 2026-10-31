// Command gateway is the public TLS relay in front of the profile relays.
//
// It terminates TLS on 8443 and forwards by peeking at the first bytes:
//   - TLS ClientHello  -> read SNI, check the domain whitelist, splice raw bytes
//   - CONNECT host:443 -> check the host, splice raw bytes
//
// Only whitelisted domains are reachable, so a leaked card key cannot be turned
// into a general-purpose proxy. The client also has to present the tunnel
// secret as a bearer token on CONNECT.
package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// helloReadTimeout bounds how long a silent socket may occupy a slot.
	helloReadTimeout = 10 * time.Second
	// dialTimeout bounds the upstream dial.
	dialTimeout = 10 * time.Second
	// maxSNI keeps the ClientHello peek bounded.
	maxSNI = 2048
	// The sing-box inbound range. A launcher names its profile's port; anything
	// outside the range is refused rather than dialled.
	minProfilePort = 10001
	maxProfilePort = 11000
)

// whitelist holds suffix patterns such as ".anthropic.com".
type whitelist struct {
	suffixes []string
	exact    map[string]struct{}
}

func newWhitelist(domains []string) *whitelist {
	w := &whitelist{exact: map[string]struct{}{}}
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if strings.HasPrefix(domain, "*.") {
			bare := domain[2:]
			w.suffixes = append(w.suffixes, "."+bare)
			w.exact[bare] = struct{}{}
			continue
		}
		if strings.HasPrefix(domain, ".") {
			w.suffixes = append(w.suffixes, domain)
			continue
		}
		w.exact[domain] = struct{}{}
	}
	return w
}

func (w *whitelist) allows(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	// Strip a trailing dot from the FQDN form, then any :port.
	host = strings.TrimSuffix(host, ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if _, ok := w.exact[host]; ok {
		return true
	}
	for _, suffix := range w.suffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// peekClientHello returns the SNI from a TLS ClientHello without consuming it.
// errNoSNI means the ClientHello was fine but named no host -- what Go sends
// when it dials an IP address, so it cannot be treated as a parse failure.
var errNoSNI = errors.New("no SNI in ClientHello")

func peekClientHello(reader *bufio.Reader) (sni string, record []byte, err error) {
	header, err := reader.Peek(5)
	if err != nil {
		return "", nil, err
	}
	if header[0] != 0x16 {
		return "", nil, errors.New("not a TLS handshake")
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length <= 0 || length > 16384 {
		return "", nil, errors.New("bad handshake length")
	}
	// Consume the record, keeping a copy: a terminated handshake has to replay it
	// to tls.Server, because the client will not send anything else until it sees
	// a ServerHello.
	full, err := reader.Peek(5 + length)
	if err != nil {
		return "", nil, err
	}
	record = append([]byte(nil), full...)
	if _, err := reader.Discard(5 + length); err != nil {
		return "", nil, err
	}
	sni, err = parseSNI(record[5:])
	return sni, record, err
}

// parseSNI walks the ClientHello extensions looking for server_name (0).
func parseSNI(body []byte) (string, error) {
	if len(body) < 4+2+32 {
		return "", errors.New("handshake too short")
	}
	pos := 4 + 2 + 32 // handshake hdr, version, random
	if pos >= len(body) {
		return "", errors.New("truncated session id")
	}
	pos += 1 + int(body[pos]) // session id
	if pos+2 > len(body) {
		return "", errors.New("truncated cipher suites")
	}
	pos += 2 + int(binary.BigEndian.Uint16(body[pos:pos+2]))
	if pos >= len(body) {
		return "", errors.New("truncated compression")
	}
	pos += 1 + int(body[pos])
	if pos+2 > len(body) {
		return "", errNoSNI
	}
	extLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
	pos += 2
	end := pos + extLen
	if end > len(body) {
		end = len(body)
	}
	// Walked the whole extension block without a server_name entry.
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(body[pos : pos+2])
		extSize := int(binary.BigEndian.Uint16(body[pos+2 : pos+4]))
		pos += 4
		if pos+extSize > end {
			break
		}
		if extType == 0x0000 { // server_name
			data := body[pos : pos+extSize]
			if len(data) < 5 {
				return "", errNoSNI
			}
			nameLen := int(binary.BigEndian.Uint16(data[3:5]))
			if 5+nameLen > len(data) {
				return "", errors.New("sni truncated")
			}
			return string(data[5 : 5+nameLen]), nil
		}
		pos += extSize
	}
	return "", errNoSNI
}

type gateway struct {
	domains *whitelist
	secret  string
	debug   bool
	// Port span a launcher may name; zero means the sing-box default range.
	minPort int
	maxPort int
	// Certificate for TLS terminated at the gateway; nil disables termination.
	certificate *tls.Certificate
}

// handshakeConn replays the bytes already consumed during the peek.
type handshakeConn struct {
	net.Conn
	reader io.Reader
}

func (c *handshakeConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (g *gateway) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(helloReadTimeout))

	reader := bufio.NewReader(conn)
	head, err := reader.Peek(1)
	if err != nil {
		return
	}

	if head[0] == 0x16 {
		g.handleTLS(conn, reader)
		return
	}
	g.handleConnect(conn, reader)
}

// handleTLS accepts a TLS client.
//
// Two shapes end up here, distinguished by SNI:
//
//   - The client dialled a whitelisted origin directly (SNI is that origin).
//     The ClientHello is replayed and spliced to the origin: the TLS session runs
//     end to end, so certificate pinning inside Claude still works.
//   - The client dialled the gateway itself. There is either no SNI (an IP
//     address was given) or a non-whitelisted one, so the handshake is terminated
//     here and the tunnel is served inside, where the CONNECT target is checked
//     against the whitelist instead.
func (g *gateway) handleTLS(conn net.Conn, reader *bufio.Reader) {
	sni, record, err := peekClientHello(reader)
	if err != nil && !errors.Is(err, errNoSNI) {
		if g.debug {
			log.Printf("tls: %v", err)
		}
		return
	}

	// Everything consumed from `reader` goes back in front of the live socket.
	replay := &handshakeConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(record), reader, conn)}

	if sni != "" && g.domains.allows(sni) {
		upstream, err := tls.Dial("tcp", net.JoinHostPort(sni, "443"), &tls.Config{ServerName: sni})
		if err != nil {
			if g.debug {
				log.Printf("tls dial %s: %v", sni, err)
			}
			return
		}
		defer upstream.Close()
		_ = conn.SetDeadline(time.Time{})
		splice(replay, upstream)
		return
	}

	if g.certificate == nil {
		if g.debug {
			log.Printf("tls: %q needs termination but no certificate is configured", sni)
		}
		return
	}
	tunneled := tls.Server(replay, &tls.Config{Certificates: []tls.Certificate{*g.certificate}})
	defer tunneled.Close()
	if err := tunneled.Handshake(); err != nil {
		if g.debug {
			log.Printf("tls handshake: %v", err)
		}
		return
	}
	_ = tunneled.SetDeadline(time.Now().Add(helloReadTimeout))
	g.handleConnect(tunneled, bufio.NewReader(tunneled))
}

func (g *gateway) handleConnect(conn net.Conn, reader *bufio.Reader) {

	request, err := readRequestHead(reader)
	if err != nil {
		return
	}
	if request.method != "CONNECT" {
		fmt.Fprint(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if g.secret != "" && request.bearer != g.secret {
		fmt.Fprint(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if !g.domains.allows(request.host) {
		if g.debug {
			log.Printf("connect: blocked %s", request.host)
		}
		fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}

	upstream, err := g.dialOrigin(request)
	if err != nil {
		if g.debug {
			log.Printf("dial %s via %q: %v", request.host, request.profile, err)
		}
		fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()

	fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = conn.SetDeadline(time.Time{})
	splice(&handshakeConn{Conn: conn, reader: reader}, upstream)
}

type requestHead struct {
	method  string
	host    string
	port    string
	bearer  string
	profile string // the profile's local sing-box port, from x-profile-port
}

func readRequestHead(reader *bufio.Reader) (requestHead, error) {
	var head requestHead
	line, err := reader.ReadString('\n')
	if err != nil {
		return head, err
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return head, errors.New("malformed request line")
	}
	head.method = fields[0]
	target := fields[1]
	if len(target) > maxSNI {
		return head, errors.New("target too long")
	}
	host, port, splitErr := net.SplitHostPort(target)
	if splitErr != nil {
		host, port = target, "443"
	}
	head.host, head.port = host, port

	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return head, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return head, nil
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "proxy-authorization":
			head.bearer = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "Bearer "))
		case "x-profile-port":
			head.profile = strings.TrimSpace(value)
		}
	}
}

// dialOrigin opens the connection to the requested host.
//
// The traffic has to leave from the profile's residential IP, so the dial goes
// through that profile's sing-box inbound (a "mixed" listener, which answers
// CONNECT) rather than from the gateway's own address. Without the header the
// gateway falls back to a direct dial, which is right for a single-machine run
// but reported by the launcher's kill switch as an IP mismatch -- exactly the
// signal that the chain is missing.
func (g *gateway) dialOrigin(request requestHead) (net.Conn, error) {
	if request.profile == "" || strings.HasPrefix(request.profile, "0") {
		return net.DialTimeout("tcp", net.JoinHostPort(request.host, request.port), dialTimeout)
	}
	port, err := strconv.Atoi(request.profile)
	low, high := g.profileRange()
	if err != nil || port < low || port > high {
		return nil, fmt.Errorf("bad x-profile-port %q", request.profile)
	}
	relay, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", request.profile), dialTimeout)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(request.host, request.port)
	_ = relay.SetDeadline(time.Now().Add(dialTimeout))
	// sing-box's inbound does not authenticate: it is bound to loopback and every
	// allowed connection already proved its tunnel secret here.
	if _, err := fmt.Fprintf(relay, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		relay.Close()
		return nil, err
	}
	reader := bufio.NewReader(relay)
	status, err := reader.ReadString('\n')
	if err != nil {
		relay.Close()
		return nil, err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			relay.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if !strings.Contains(status, " 200") {
		relay.Close()
		return nil, fmt.Errorf("relay refused %s: %s", target, strings.TrimSpace(status))
	}
	_ = relay.SetDeadline(time.Time{})
	if reader.Buffered() > 0 {
		buffered, _ := reader.Peek(reader.Buffered())
		return &prefixedConn{Conn: relay, buffered: buffered}, nil
	}
	return relay, nil
}

// profileRange is the allowed sing-box port span, overridable for tests.
func (g *gateway) profileRange() (int, int) {
	if g.minPort != 0 && g.maxPort != 0 {
		return g.minPort, g.maxPort
	}
	return minProfilePort, maxProfilePort
}

// prefixedConn replays bytes the relay sent along with its 200.
type prefixedConn struct {
	net.Conn
	buffered []byte
}

func (c *prefixedConn) Read(p []byte) (int, error) {
	if len(c.buffered) > 0 {
		n := copy(p, c.buffered)
		c.buffered = c.buffered[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
}

func (w *whitelist) String() string {
	return strings.Join(append(w.suffixes, keys(w.exact)...), ",")
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func main() {
	listen := flag.String("listen", ":8443", "listen address")
	domainsFlag := flag.String("domains", "", "comma-separated whitelist, e.g. *.anthropic.com")
	debug := flag.Bool("debug", false, "log rejected handshakes")
	certPath := flag.String("cert", envOr("CCE_TUNNEL_CERT", "data/gateway/tls.crt"), "TLS certificate for gateway-terminated connections")
	keyPath := flag.String("key", envOr("CCE_TUNNEL_KEY", "data/gateway/tls.key"), "TLS key matching --cert")
	flag.Parse()

	domains := []string{"*.anthropic.com", "*.claude.ai", "*.stripe.com", "*.cloudflare.com", "ipinfo.io", "ip-api.com"}
	if *domainsFlag != "" {
		domains = strings.Split(*domainsFlag, ",")
	}
	secret := os.Getenv("CCE_TUNNEL_SECRET")

	certificate, err := loadCertificate(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}

	g := &gateway{domains: newWhitelist(domains), secret: secret, debug: *debug, certificate: certificate}

	// Always a plain TCP listener. The gateway is a pass-through, so the bytes it
	// inspects have to be the original TLS records; termination happens at the
	// real upstream, which keeps client-side certificate pinning working.
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	log.Printf("gateway: %s with %d whitelist entries", *listen, len(domains))

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go g.handle(conn)
	}
}

// loadCertificate reads the gateway's own keypair, generating and persisting a
// self-signed one on first run.
//
// Only connections where the client dialled the gateway (rather than an origin)
// are terminated here; see handleTLS. Pinning the origin certificate is
// untouched, so Claude's own pinning keeps working either way.
func loadCertificate(certPath, keyPath string) (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err == nil {
		return &certificate, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "claude-cluster-gateway"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// A self-signed certificate is only usable if it can be validated for the
	// name the launcher dials. CCE_TUNNEL_SAN names that (comma separated
	// hostnames/IPs); loopback is always included so a local run works.
	for _, name := range []string{"127.0.0.1", "::1"} {
		template.IPAddresses = append(template.IPAddresses, net.ParseIP(name))
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	if dir := filepath.Dir(certPath); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, pemCert, 0o600); err != nil {
		return nil, err
	}
	derKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derKey})
	if err := os.WriteFile(keyPath, pemKey, 0o600); err != nil {
		return nil, err
	}
	log.Printf("certificate: generated %s (pin it with CCE_TUNNEL_CA)", certPath)

	loaded, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return &loaded, nil
}

// certificateNames is the DNS name list baked into a generated certificate.
func certificateNames() []string {
	names := []string{"localhost"}
	if host, err := os.Hostname(); err == nil && host != "" {
		names = append(names, host)
	}
	for _, extra := range strings.Split(os.Getenv("CCE_TUNNEL_SAN"), ",") {
		if extra = strings.TrimSpace(extra); extra != "" {
			names = append(names, extra)
		}
	}
	return names
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// ensure bytes import is used even if future edits drop the packet parser
var _ = bytes.MinRead
