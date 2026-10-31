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
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWhitelistAllowsSubdomains(t *testing.T) {
	w := newWhitelist([]string{"*.anthropic.com", "ipinfo.io"})
	allowed := []string{
		"api.anthropic.com",
		"claude.ai.anthropic.com",
		"api.anthropic.com.",
		"anthropic.com", // apex covered by the wildcard entry
		"api.ANTHROPIC.com",
		"ipinfo.io",
	}
	for _, host := range allowed {
		if !w.allows(host) {
			t.Errorf("expected %q to be allowed", host)
		}
	}
}

func TestWhitelistBlocksEverythingElse(t *testing.T) {
	w := newWhitelist([]string{"*.anthropic.com"})
	blocked := []string{
		"evil.com",
		"anthropic.com.evil.com",
		"notanthropic.com",
		"",
	}
	for _, host := range blocked {
		if w.allows(host) {
			t.Errorf("expected %q to be blocked", host)
		}
	}
}

func TestWhitelistStripsPort(t *testing.T) {
	w := newWhitelist([]string{"*.claude.ai"})
	if !w.allows("api.claude.ai:443") {
		t.Fatal("host:port form should be accepted")
	}
}

func TestWhitelistExactMatch(t *testing.T) {
	w := newWhitelist([]string{"ip-api.com"})
	if !w.allows("ip-api.com") || w.allows("free.ip-api.com") {
		t.Fatal("exact entry must not become a suffix match")
	}
}

// buildClientHello assembles a minimal but structurally valid ClientHello.
func buildClientHello(sni string) []byte {
	name := []byte(sni)
	entry := append([]byte{0x00, byte(len(name) >> 8), byte(len(name))}, name...)
	serverName := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	ext := append([]byte{0x00, 0x00, byte(len(serverName) >> 8), byte(len(serverName))}, serverName...)

	pos := make([]byte, 0, 64)
	pos = append(pos, 0x03, 0x03)             // version
	pos = append(pos, make([]byte, 32)...)    // random
	pos = append(pos, 0x00)                   // empty session id
	pos = append(pos, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	pos = append(pos, 0x01, 0x00)             // null compression
	pos = append(pos, byte(len(ext)>>8), byte(len(ext)))
	pos = append(pos, ext...)

	handshake := append([]byte{0x01, byte(len(pos) >> 16), byte(len(pos) >> 8), byte(len(pos))}, pos...)
	record := append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	return record
}

func TestParseSNIRecoversHostname(t *testing.T) {
	got, err := parseSNI(buildClientHello("api.anthropic.com")[5:])
	if err != nil {
		t.Fatalf("parseSNI: %v", err)
	}
	if got != "api.anthropic.com" {
		t.Fatalf("got %q, want api.anthropic.com", got)
	}
}

func TestPeekClientHelloReadsRecord(t *testing.T) {
	record := buildClientHello("claude.ai")
	got, replayed, err := peekClientHello(bufio.NewReader(bytes.NewReader(record)))
	if err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	if got != "claude.ai" {
		t.Fatalf("got %q", got)
	}
	// The record must come back byte-identical: a terminated handshake has to
	// replay it, byte for byte, or tls.Server cannot continue.
	if !bytes.Equal(replayed, record) {
		t.Fatal("peek did not return the record it consumed")
	}
}

func TestPeekClientHelloConsumesTheRecord(t *testing.T) {
	record := buildClientHello("claude.ai")
	reader := bufio.NewReader(bytes.NewReader(append(record, "rest"...)))
	if _, _, err := peekClientHello(reader); err != nil {
		t.Fatalf("peekClientHello: %v", err)
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if string(rest) != "rest" {
		t.Fatalf("bytes after the record = %q, want %q", rest, "rest")
	}
}

func TestPeekClientHelloRejectsPlaintext(t *testing.T) {
	if _, _, err := peekClientHello(bufio.NewReader(strings.NewReader("GET / HTTP/1.1\r\n\r\n"))); err == nil {
		t.Fatal("expected an error for a non-TLS record")
	}
}

// TestGatewayTerminatesWhenClientDialsTheGateway covers the launcher's case: it
// dials the gateway by IP, so the ClientHello has no SNI and nothing to
// whitelist yet. The handshake must be terminated here and the CONNECT inside
// checked instead.
func TestGatewayTerminatesWhenClientDialsTheGateway(t *testing.T) {
	certificate := testCertificate(t)
	g := &gateway{domains: newWhitelist([]string{"*.anthropic.com", "127.0.0.1"}), certificate: &certificate}

	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "origin")
	}()

	front := startFront(t, g)
	conn, err := tls.Dial("tcp", front, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, originPort, _ := net.SplitHostPort(origin.Addr().String())
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%s HTTP/1.1\r\n\r\n", originPort)
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(response, "200") {
		t.Fatalf("response = %q", response)
	}
	body := make([]byte, len("origin"))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read origin: %v", err)
	}
	if string(body) != "origin" {
		t.Fatalf("body = %q", body)
	}
}

func startFront(t *testing.T, g *gateway) string {
	t.Helper()
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = front.Close() })
	go func() {
		for {
			conn, err := front.Accept()
			if err != nil {
				return
			}
			go g.handle(conn)
		}
	}()
	return front.Addr().String()
}

func testCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gateway"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestParseSNIRejectsTruncated(t *testing.T) {
	if _, err := parseSNI([]byte{0x03, 0x03}); err == nil {
		t.Fatal("expected an error for a short handshake")
	}
}

func TestReadRequestHeadParsesConnectAndBearer(t *testing.T) {
	raw := "CONNECT api.anthropic.com:443 HTTP/1.1\r\n" +
		"Host: api.anthropic.com:443\r\n" +
		"Proxy-Authorization: Bearer s3cret\r\n\r\n"
	head, err := readRequestHead(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("readRequestHead: %v", err)
	}
	if head.method != "CONNECT" || head.host != "api.anthropic.com" || head.port != "443" {
		t.Fatalf("bad parse: %+v", head)
	}
	if head.bearer != "s3cret" {
		t.Fatalf("bearer = %q", head.bearer)
	}
}

// TestConnectTunnelEndToEnd dials a local echo server through the gateway.
func TestConnectTunnelEndToEnd(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("pong"))
			}(conn)
		}
	}()

	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	g := &gateway{domains: newWhitelist([]string{"127.0.0.1"})}
	go func() {
		for {
			conn, err := front.Accept()
			if err != nil {
				return
			}
			go g.handle(conn)
		}
	}()

	conn, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	target := echo.Addr().(*net.TCPAddr)
	// The gateway always dials 443 for CONNECT unless a port is given.
	if _, err := conn.Write([]byte("CONNECT " + net.JoinHostPort(target.IP.String(), itoa(target.Port)) + " HTTP/1.1\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "200") {
		t.Fatalf("expected 200, got %q", line)
	}
	for {
		line, err = reader.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}
	body := make([]byte, 4)
	if _, err := io.ReadFull(reader, body); err != nil {
		t.Fatal(err)
	}
	if string(body) != "pong" {
		t.Fatalf("got %q, want pong", body)
	}
}

func itoa(n int) string {
	var buf [8]byte
	pos := len(buf)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// TestBlockedDomainClosesConnection verifies the whitelist is enforced.
func TestBlockedDomainClosesConnection(t *testing.T) {
	front, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	g := &gateway{domains: newWhitelist([]string{"*.anthropic.com"})}
	go func() {
		for {
			conn, err := front.Accept()
			if err != nil {
				return
			}
			go g.handle(conn)
		}
	}()

	conn, err := net.Dial("tcp", front.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(buildClientHello("evil.example")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		n, _ := conn.Read(buf)
		if n > 0 {
			t.Fatal("expected the gateway to close a blocked TLS connection")
		}
	}
}

func TestReadRequestHeadParsesProfilePort(t *testing.T) {
	raw := "CONNECT api.anthropic.com:443 HTTP/1.1\r\n" +
		"Proxy-Authorization: Bearer s3cret\r\n" +
		"X-Profile-Port: 10432\r\n\r\n"
	head, err := readRequestHead(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("readRequestHead: %v", err)
	}
	if head.profile != "10432" {
		t.Fatalf("profile port = %q", head.profile)
	}
}

// TestDialOriginGoesThroughRelay proves the origin dial leaves via the
// profile's sing-box inbound instead of the gateway's own address -- the whole
// point of the header.
func TestDialOriginGoesThroughRelay(t *testing.T) {
	relay, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	_, relayPort, _ := net.SplitHostPort(relay.Addr().String())

	// No room for a real sing-box on the fixed port range, so the test tells
	// the gateway to use the ephemeral listener's own number.
	want := "api.anthropic.com:443"
	requested := make(chan string, 1)
	go func() {
		conn, err := relay.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		line, _ := reader.ReadString('\n')
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			requested <- fields[1]
		}
		for {
			header, err := reader.ReadString('\n')
			if err != nil || header == "\r\n" {
				break
			}
		}
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		io.WriteString(conn, "relayed")
	}()

	g := &gateway{domains: newWhitelist([]string{"*.anthropic.com"}), minPort: 1, maxPort: 65535}

	conn, err := g.dialOrigin(requestHead{host: "api.anthropic.com", port: "443", profile: relayPort})
	if err != nil {
		t.Fatalf("dialOrigin: %v", err)
	}
	defer conn.Close()

	select {
	case got := <-requested:
		if got != want {
			t.Fatalf("relay asked for %q, want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay was never asked to connect")
	}

	body := make([]byte, len("relayed"))
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("read through relay: %v", err)
	}
	if string(body) != "relayed" {
		t.Fatalf("body = %q", body)
	}
}

func TestDialOriginFallsBackWithoutProfilePort(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	host, port, _ := net.SplitHostPort(origin.Addr().String())
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	g := &gateway{domains: newWhitelist([]string{"*.anthropic.com"})}
	conn, err := g.dialOrigin(requestHead{host: host, port: port})
	if err != nil {
		t.Fatalf("dialOrigin: %v", err)
	}
	conn.Close()
}

func TestDialOriginRejectsOutOfRangePort(t *testing.T) {
	g := &gateway{domains: newWhitelist([]string{"*.anthropic.com"})}
	for _, port := range []string{"80", "12000", "not-a-port"} {
		if _, err := g.dialOrigin(requestHead{host: "127.0.0.1", port: "1", profile: port}); err == nil {
			t.Errorf("profile port %q should be refused", port)
		}
	}
}

var _ = binary.BigEndian
var _ = tls.VersionTLS13
