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
	"os"
	"path/filepath"
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
	g := &gateway{secrets: testSecrets(t, "s3cret", 10432), domains: newWhitelist([]string{"*.anthropic.com", "127.0.0.1"}), certificate: &certificate}

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
	fmt.Fprintf(conn, "CONNECT 127.0.0.1:%s HTTP/1.1\r\nProxy-Authorization: Bearer s3cret\r\nx-profile-port: 10432\r\n\r\n", originPort)
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(response, "502") {
		t.Fatalf("missing relay must be refused, got %q", response)
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

func testSecrets(t *testing.T, secret string, port int) *secrets {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets")
	line := fmt.Sprintf("cce-test %s 2099-01-01T00:00:00Z %d\n", secret, port)
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return newSecrets(path)
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

// A missing relay must not fall back to a direct connection from the gateway.
func TestConnectDoesNotFallBackToDirectOrigin(t *testing.T) {
	certificate := testCertificate(t)
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
	g := &gateway{secrets: testSecrets(t, "s3cret", 10432), domains: newWhitelist([]string{"127.0.0.1"}), certificate: &certificate}
	go func() {
		for {
			conn, err := front.Accept()
			if err != nil {
				return
			}
			go g.handle(conn)
		}
	}()

	conn, err := tls.Dial("tcp", front.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	target := echo.Addr().(*net.TCPAddr)
	// The gateway always dials 443 for CONNECT unless a port is given.
	if _, err := conn.Write([]byte("CONNECT " + net.JoinHostPort(target.IP.String(), itoa(target.Port)) + " HTTP/1.1\r\nProxy-Authorization: Bearer s3cret\r\nx-profile-port: 10432\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "502") {
		t.Fatalf("expected 502 without relay, got %q", line)
	}
}

func TestSecretsAuthorisesExportedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets")
	write := func(body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	set := newSecrets(path)

	write("# card_key secret expires_at profile_port\ncce-a aaa 2099-01-01T00:00:00Z 10432\n")
	if !set.authorizes("aaa", "10432") {
		t.Fatal("exported secret should authorise")
	}
	if set.authorizes("aaa", "10433") || set.authorizes("aaa", "") || set.authorizes("bbb", "10432") {
		t.Fatal("unknown or empty secret should not authorise")
	}

	// A revocation rewrites the file; the change has to land without a restart.
	write("cce-b bbb 2099-01-01T00:00:00Z 10433\n")
	if set.authorizes("aaa", "10432") {
		t.Error("removed secret still authorises")
	}
	if !set.authorizes("bbb", "10433") {
		t.Error("freshly exported secret rejected")
	}

	write("cce-old ccc 2000-01-01T00:00:00Z 10432\n")
	if set.authorizes("ccc", "10432") {
		t.Error("expired secret should not authorise")
	}
}

func TestGatewayRequiresSecretFile(t *testing.T) {
	if newSecrets("").enabled() {
		t.Fatal("gateway must refuse startup without a secret file")
	}
}

func TestCachedGrantExpiresWithoutFileChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets")
	expires := time.Now().Add(1500 * time.Millisecond).UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(path, []byte("cce-a aaa "+expires+" 10432\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	set := newSecrets(path)
	if !set.authorizes("aaa", "10432") {
		t.Fatal("grant should initially be live")
	}
	time.Sleep(1600 * time.Millisecond)
	if set.authorizes("aaa", "10432") {
		t.Fatal("cached expired grant must not remain live")
	}
}

func TestConnectSecretCannotSelectAnotherProfile(t *testing.T) {
	certificate := testCertificate(t)
	g := &gateway{secrets: testSecrets(t, "s3cret", 10432), domains: newWhitelist([]string{"127.0.0.1"}), certificate: &certificate}
	front := startFront(t, g)
	for _, profile := range []string{"", "10433"} {
		conn, err := tls.Dial("tcp", front, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintf(conn, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nProxy-Authorization: Bearer s3cret\r\nx-profile-port: %s\r\n\r\n", profile)
		line, err := bufio.NewReader(conn).ReadString('\n')
		conn.Close()
		if err != nil || !strings.Contains(line, "407") {
			t.Fatalf("profile %q: got %q, %v; want 407", profile, line, err)
		}
	}
}

func TestPlaintextConnectIsRefused(t *testing.T) {
	certificate := testCertificate(t)
	g := &gateway{secrets: testSecrets(t, "s3cret", 10432), domains: newWhitelist([]string{"127.0.0.1"}), certificate: &certificate}
	conn, err := net.Dial("tcp", startFront(t, g))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nProxy-Authorization: Bearer s3cret\r\nx-profile-port: 10432\r\n\r\n")
	if _, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
		t.Fatal("plaintext CONNECT must not receive a proxy response")
	}
}

func TestRawTLSCannotBypassConnectAuthentication(t *testing.T) {
	certificate := testCertificate(t)
	g := &gateway{secrets: testSecrets(t, "s3cret", 10432), domains: newWhitelist([]string{"localhost"}), certificate: &certificate}
	front := startFront(t, g)
	conn, err := tls.Dial("tcp", front, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
		t.Fatal("raw TLS to an origin name must be rejected")
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
	g := &gateway{secrets: newSecrets(""), domains: newWhitelist([]string{"*.anthropic.com"})}
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

	g := &gateway{secrets: newSecrets(""), domains: newWhitelist([]string{"*.anthropic.com"}), minPort: 1, maxPort: 65535}

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

func TestDialOriginRejectsMissingProfilePort(t *testing.T) {
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

	g := &gateway{secrets: newSecrets(""), domains: newWhitelist([]string{"*.anthropic.com"})}
	conn, err := g.dialOrigin(requestHead{host: host, port: port})
	if err == nil {
		conn.Close()
		t.Fatal("missing profile port must be rejected")
	}
}

func TestDialOriginRejectsOutOfRangePort(t *testing.T) {
	g := &gateway{secrets: newSecrets(""), domains: newWhitelist([]string{"*.anthropic.com"})}
	for _, port := range []string{"80", "12000", "not-a-port"} {
		if _, err := g.dialOrigin(requestHead{host: "127.0.0.1", port: "1", profile: port}); err == nil {
			t.Errorf("profile port %q should be refused", port)
		}
	}
}

func TestGeneratedCertificateIsUsableForTheDialledName(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CCE_TUNNEL_SAN", "gw.example.com,203.0.113.55")
	certificate, err := loadCertificate(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatalf("loadCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// An IP in CCE_TUNNEL_SAN has to land in IPAddresses; writing it as a DNS
	// name makes every client that dials the bare address fail verification.
	if err := leaf.VerifyHostname("203.0.113.55"); err != nil {
		t.Errorf("IP SAN is not usable: %v", err)
	}
	for _, dns := range leaf.DNSNames {
		if net.ParseIP(dns) != nil {
			t.Errorf("%q was written as a DNS name", dns)
		}
	}
	if err := leaf.VerifyHostname("gw.example.com"); err != nil {
		t.Errorf("generated certificate does not cover the configured name: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("loopback should always be covered: %v", err)
	}
	// A generated keypair has to survive a restart, otherwise the pin breaks.
	again, err := loadCertificate(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !bytes.Equal(again.Certificate[0], certificate.Certificate[0]) {
		t.Error("certificate was regenerated instead of reused")
	}
}

var _ = binary.BigEndian
var _ = tls.VersionTLS13
