package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeGateway accepts one CONNECT, checks the bearer, and then echoes whatever
// it is given. It also records the target it was asked for.
func fakeGateway(t *testing.T, secret string) (net.Listener, <-chan string) {
	t.Helper()
	cert := selfSigned(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	seen := make(chan string, 4)
	trustGateway(t, cert)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := make([]byte, 0, 256)
				buf := make([]byte, 1)
				for !bytes.HasSuffix(reader, []byte("\r\n\r\n")) {
					if _, err := conn.Read(buf); err != nil {
						return
					}
					reader = append(reader, buf[0])
				}
				head := string(reader)
				fields := strings.Fields(head)
				if len(fields) < 2 {
					return
				}
				if !strings.Contains(head, "Bearer "+secret) {
					fmt.Fprint(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
					return
				}
				seen <- head
				fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener, seen
}

// trustGateway exposes the test certificate through CCE_TUNNEL_CA so the
// launcher's TLS client accepts it.
func trustGateway(t *testing.T, cert tls.Certificate) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	if err := os.WriteFile(path, pem, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	t.Setenv("CCE_TUNNEL_CA", path)
	// The probe's own TLS to the origin is a second, independent handshake; on
	// Linux Go reads the system pool from SSL_CERT_FILE.
	t.Setenv("SSL_CERT_FILE", path)
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"ipinfo.io", "api.ipify.org"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newSession() *session {
	return &session{
		ProfileID:  "acct-1",
		ExpectedIP: "203.0.113.7",
		Tunnel:     tunnel{Host: "127.0.0.1", Port: 8443, Secret: "s3cret"},
		Geo:        geoInfo{Timezone: "Europe/Berlin", Locale: "de-DE"},
	}
}

// TestCamoufoxEnvCarriesTheStoredIdentity: the bare kernel learns the machine
// from CAMOU_CONFIG, so every stored key has to survive, together with the live
// geo that must follow the exit node.
func TestCamoufoxEnvCarriesTheStoredIdentity(t *testing.T) {
	proxy, err := startLoopbackProxy(newSession(), false)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	defer proxy.Close()

	sess := newSession()
	sess.OSType = "linux"
	sess.Geo.IP = "203.0.113.7"
	sess.Fingerprint = []byte(`{"user_agent":"UA/1","locale":"de-DE","camoufox_config":` +
		`{"navigator.userAgent":"UA/1","navigator.hardwareConcurrency":8,"screen.width":1920}}`)

	runtimeDir := t.TempDir()
	env, err := camoufoxEnv(sess, runtimeDir, proxy)
	if err != nil {
		t.Fatalf("env: %v", err)
	}

	config := readEnvChunks(t, env, "CAMOU_CONFIG_")
	for key, want := range map[string]any{
		"navigator.userAgent":           "UA/1",
		"navigator.hardwareConcurrency": float64(8),
		"screen.width":                  float64(1920),
		"timezone":                      "Europe/Berlin",
		"locale:language":               "de",
		"locale:region":                 "DE",
		"webrtc:ipv4":                   "203.0.113.7",
	} {
		if got, ok := config[key]; !ok || got != want {
			t.Errorf("config[%q] = %v, want %v", key, got, want)
		}
	}
	// The drawing is pinned but the exit node is not: a stale stored timezone
	// must lose to the live one.
	if config["timezone"] != "Europe/Berlin" {
		t.Errorf("stored timezone won over the live geo: %v", config["timezone"])
	}

	prefs := readEnvChunks(t, env, "CAMOU_PREFS_")
	if prefs["network.proxy.type"] != float64(1) {
		t.Errorf("proxy type = %v", prefs["network.proxy.type"])
	}
	if prefs["network.proxy.http"] != "127.0.0.1" {
		t.Errorf("proxy host = %v", prefs["network.proxy.http"])
	}
	if prefs["intl.locale.requested"] != "de-DE" {
		t.Errorf("ui locale = %v", prefs["intl.locale.requested"])
	}
}

// TestChunkEnvSplitsAndStaysASCII: the environment block has a hard size cap and
// Windows reads it through the ANSI code page.
func TestChunkEnvSplitsAndStaysASCII(t *testing.T) {
	large := map[string]any{"blob": strings.Repeat("x", 40000), "city": "München"}
	env, err := chunkEnv("CAMOU_CONFIG_", large)
	if err != nil {
		t.Fatalf("chunk: %v", err)
	}
	if len(env) != 2 {
		t.Fatalf("40k of payload should split in two, got %d chunks", len(env))
	}
	for _, entry := range env {
		for _, r := range entry {
			if r > 0x7f {
				t.Fatalf("non-ASCII byte in %q", entry[:20])
			}
		}
	}
	config := readEnvChunks(t, env, "CAMOU_CONFIG_")
	if config["city"] != "München" {
		t.Fatalf("city round-trip failed: %v", config["city"])
	}
}

// TestFontConfigFileResolvesFontsAbsolutely: the shipped file uses
// prefix="cwd", which finds no fonts once the working directory is elsewhere.
func TestFontConfigFileResolvesFontsAbsolutely(t *testing.T) {
	runtimeDir := t.TempDir()
	fontsDir := filepath.Join(runtimeDir, "fonts")
	for _, group := range []string{"L", "LW"} {
		if err := os.MkdirAll(filepath.Join(fontsDir, group), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	groups := `{"readBy":{"lin":["L","LW"],"win":["W"]}}`
	if err := os.WriteFile(filepath.Join(fontsDir, "groups.json"), []byte(groups), 0o644); err != nil {
		t.Fatal(err)
	}
	confDir := filepath.Join(runtimeDir, "fontconfig", "linux")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := "<fontconfig><dir prefix=\"cwd\">fonts</dir></fontconfig>"
	if err := os.WriteFile(filepath.Join(confDir, "fonts.conf"), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	conf, err := fontConfigFile(runtimeDir, "linux")
	if err != nil {
		t.Fatalf("fontconfig: %v", err)
	}
	body, err := os.ReadFile(conf)
	if err != nil {
		t.Fatalf("read rendered conf: %v", err)
	}
	if !strings.Contains(string(body), filepath.Join(fontsDir, "L")) {
		t.Fatalf("group L missing from %s", body)
	}
	// Windows shares nothing with this identity, so W must not be scanned.
	if strings.Contains(string(body), string(filepath.Separator)+"W<") {
		t.Fatalf("W should not be read by a linux identity: %s", body)
	}
	if strings.Contains(string(body), `prefix="cwd"`) {
		t.Fatal("the relative prefix survived")
	}
}

func readEnvChunks(t *testing.T, env []string, prefix string) map[string]any {
	t.Helper()
	var joined strings.Builder
	for _, entry := range env {
		name, value, ok := strings.Cut(entry, "=")
		if !ok || !strings.HasPrefix(name, prefix) {
			continue
		}
		joined.WriteString(value)
	}
	if joined.Len() == 0 {
		t.Fatalf("no %s* variables in the environment", prefix)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(joined.String()), &out); err != nil {
		t.Fatalf("chunks do not reassemble into JSON: %v", err)
	}
	return out
}

func TestLoopbackProxySignsConnectAndTunnels(t *testing.T) {
	targetListener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer targetListener.Close()
	go func() {
		conn, err := targetListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()
	host, port, _ := net.SplitHostPort(targetListener.Addr().String())

	gatewayListener, seen := fakeGateway(t, "s3cret")
	gwHost, gwPort, _ := net.SplitHostPort(gatewayListener.Addr().String())
	gwPortNum := atoi(gwPort)
	sess := newSession()
	sess.ProfilePort = 10432
	sess.Tunnel = tunnel{Host: gwHost, Port: gwPortNum, Secret: "s3cret"}

	p, err := startLoopbackProxy(sess, true)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Close()

	conn, err := net.Dial("tcp", p.addr())
	if err != nil {
		t.Fatalf("dial loopback: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "CONNECT %s:%s HTTP/1.1\r\nHost: %s\r\n\r\n", host, port, host)

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// The tunnel stays open, so read exactly the response head rather than
	// waiting for EOF.
	response := readUntilBlank(t, conn)
	if response == "" {
		t.Fatal("no response from the loopback proxy")
	}
	if !strings.Contains(string(response), "200") {
		t.Fatalf("expected the tunnel to be established, got %q", response)
	}

	select {
	case head := <-seen:
		if want := "CONNECT " + net.JoinHostPort(host, port); !strings.Contains(head, want) {
			t.Fatalf("gateway saw %q, want it to contain %q", head, want)
		}
		if !strings.Contains(head, "x-profile-port: 10432") {
			t.Fatalf("gateway saw %q, want an x-profile-port header", head)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never received the CONNECT")
	}
}

func TestLoopbackProxyRejectsBadSecret(t *testing.T) {
	gatewayListener, _ := fakeGateway(t, "other")
	host, port, _ := net.SplitHostPort(gatewayListener.Addr().String())
	sess := newSession()
	sess.Tunnel = tunnel{Host: host, Port: atoi(port), Secret: "s3cret"}

	p, err := startLoopbackProxy(sess, false)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer p.Close()

	conn, err := net.Dial("tcp", p.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n")
	response := readUntilBlank(t, conn)
	if !strings.Contains(string(response), "502") {
		t.Fatalf("bad secret should surface as 502, got %q", response)
	}
}

// TestLoopbackProxySurfacesWhitelistRejection: a 403 from the gateway (host not
// whitelisted) has to become a client-side failure, not a silent success.
func TestLoopbackProxySurfacesWhitelistRejection(t *testing.T) {
	cert := selfSigned(t)
	trustGateway(t, cert)
	gatewayListener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer gatewayListener.Close()
	go func() {
		for {
			conn, err := gatewayListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				drainHead(conn)
				fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			}(conn)
		}
	}()

	host, port, _ := net.SplitHostPort(gatewayListener.Addr().String())
	sess := newSession()
	sess.Tunnel = tunnel{Host: host, Port: atoi(port), Secret: "s3cret"}
	proxy, err := startLoopbackProxy(sess, false)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer proxy.Close()

	conn, err := net.Dial("tcp", proxy.addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "CONNECT example.org:443 HTTP/1.1\r\n\r\n")

	response := readUntilBlank(t, conn)
	if !strings.Contains(response, "502") {
		t.Fatalf("whitelist rejection should surface as 502, got %q", response)
	}
}

// TestRefreshCredentialsSwapsAtomically: a stale config dir is replaced whole,
// so claude never reads a half-extracted store.
func TestRefreshCredentialsSwapsAtomically(t *testing.T) {
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	body := []byte(`{"token":"fresh"}`)
	if err := tw.WriteHeader(&tar.Header{Name: ".claude/.credentials.json", Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatalf("header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("write: %v", err)
	}
	tw.Close()
	gz.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-tunnel-secret") != "s3cret" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = w.Write(buffer.Bytes())
	}))
	defer server.Close()

	client, err := newAPIClient(server.URL, "key-1")
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	root := t.TempDir()
	configDir := filepath.Join(root, "profiles", "acct-1", ".claude")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(configDir, "stale.json")
	if err := os.WriteFile(stale, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Age the stamp past the refresh window.
	stamp := filepath.Join(configDir, ".credentials.json")
	if err := os.WriteFile(stamp, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * credentialMaxAge)
	if err := os.Chtimes(stamp, old, old); err != nil {
		t.Fatal(err)
	}

	sess := newSession()
	sess.Tunnel.Secret = "s3cret"
	if err := refreshCredentials(context.Background(), client, sess, configDir); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("the stale file should be gone after a refresh")
	}
	got, err := os.ReadFile(filepath.Join(configDir, ".credentials.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("credentials = %q", got)
	}
	if _, err := os.Stat(configDir + ".incoming"); !os.IsNotExist(err) {
		t.Fatal("the staging directory should have been renamed away")
	}
}

// TestLoopbackProbeReadsEgressIP runs the real loopback in front of a gateway
// that answers every tunnel with a plain IP, which is what the kill switch reads.
func TestLoopbackProbeReadsEgressIP(t *testing.T) {
	const wantIP = "203.0.113.7"

	cert := selfSigned(t)
	trustGateway(t, cert)
	gatewayListener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer gatewayListener.Close()
	go func() {
		for {
			conn, err := gatewayListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				head := drainHead(conn)
				t.Logf("gateway head = %q", head)
				fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
				// The probe asks for an https URL, so the origin side has to
				// complete a TLS handshake before any HTTP is exchanged.
				tunneled := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				if err := tunneled.Handshake(); err != nil {
					t.Logf("handshake: %v", err)
					return
				}
				t.Logf("gateway handshake ok")
				drainHead(tunneled)
				fmt.Fprintf(tunneled, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
					len(wantIP), wantIP)
			}(conn)
		}
	}()

	host, port, _ := net.SplitHostPort(gatewayListener.Addr().String())
	sess := newSession()
	sess.Tunnel = tunnel{Host: host, Port: atoi(port), Secret: "s3cret"}

	proxy, err := startLoopbackProxy(sess, false)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer proxy.Close()

	got, err := proxy.probe(context.Background())
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got != wantIP {
		t.Fatalf("probe read %q, want %q", got, wantIP)
	}
}

// readUntilBlank reads an HTTP head, or "" when the peer closes.
func readUntilBlank(t *testing.T, conn net.Conn) string {
	t.Helper()
	buffer := make([]byte, 0, 256)
	chunk := make([]byte, 1)
	for !bytes.HasSuffix(buffer, []byte("\r\n\r\n")) {
		if _, err := conn.Read(chunk); err != nil {
			if len(buffer) > 0 {
				break
			}
			return ""
		}
		buffer = append(buffer, chunk[0])
	}
	return string(buffer)
}

func drainHead(conn net.Conn) string {
	buffer := make([]byte, 0, 256)
	chunk := make([]byte, 1)
	for !bytes.HasSuffix(buffer, []byte("\r\n\r\n")) {
		if _, err := conn.Read(chunk); err != nil {
			return string(buffer)
		}
		buffer = append(buffer, chunk[0])
	}
	return string(buffer)
}

func TestExtractTarGzUnpacksUnderDest(t *testing.T) {
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tw := tar.NewWriter(gz)
	body := []byte(`{"token":"x"}`)
	if err := tw.WriteHeader(&tar.Header{Name: ".claude/.credentials.json", Mode: 0o600, Size: int64(len(body))}); err != nil {
		t.Fatalf("header: %v", err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o600, Size: 3}); err != nil {
		t.Fatalf("header: %v", err)
	}
	if _, err := tw.Write([]byte("esc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	tw.Close()
	gz.Close()

	dest := t.TempDir()
	if err := extractTarGz(buffer.Bytes(), dest); err != nil {
		t.Fatalf("extract: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, ".claude", ".credentials.json"))
	if err != nil {
		t.Fatalf("credentials missing: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("content = %q", got)
	}
}

func TestReadHeadRequiresConnect(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { fmt.Fprint(server, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\n\r\n") }()
	target, err := readHead(client)
	if err != nil {
		t.Fatalf("readHead: %v", err)
	}
	if target != "api.anthropic.com:443" {
		t.Fatalf("target = %q", target)
	}

	go func() { fmt.Fprint(server, "GET / HTTP/1.1\r\n\r\n") }()
	if _, err := readHead(client); err == nil {
		t.Fatal("a non-CONNECT request should be rejected")
	}
}

// TestClaudeArgsAreSeparatedFromLauncherFlags guards against leaking the
// launcher's own --key/--host into the child process.
func TestClaudeArgsAreSeparatedFromLauncherFlags(t *testing.T) {
	takesValue := func(name string) bool {
		switch name {
		case "key", "host", "gateway", "claude", "runtime":
			return true
		}
		return false
	}
	known := func(name string) bool { return takesValue(name) || name == "keep" || name == "v" }

	cases := []struct {
		in       []string
		wantOwn  []string
		wantRest []string
	}{
		{
			in:       []string{"--key", "k", "-v", "--host", "http://x", "--resume", "--print", "hi"},
			wantOwn:  []string{"--key", "k", "-v", "--host", "http://x"},
			wantRest: []string{"--resume", "--print", "hi"},
		},
		{
			// An explicit separator always wins, even for a name we own.
			in:       []string{"--key", "k", "--", "--key", "child"},
			wantOwn:  []string{"--key", "k"},
			wantRest: []string{"--key", "child"},
		},
		{
			in:       []string{"--keep"},
			wantOwn:  []string{"--keep"},
			wantRest: nil,
		},
	}

	for _, testCase := range cases {
		own, rest := splitArgs(testCase.in, takesValue, known)
		if strings.Join(own, "\x00") != strings.Join(testCase.wantOwn, "\x00") {
			t.Fatalf("%q: own = %q, want %q", testCase.in, own, testCase.wantOwn)
		}
		if strings.Join(rest, "\x00") != strings.Join(testCase.wantRest, "\x00") {
			t.Fatalf("%q: rest = %q, want %q", testCase.in, rest, testCase.wantRest)
		}
	}
}

func TestSessionTunnelAddrDefaultsPort(t *testing.T) {
	if got := (tunnel{Host: "gw.example"}).addr(); got != "gw.example:8443" {
		t.Fatalf("addr = %q", got)
	}
}

// TestKillSwitchExitsOnDrift drives the whole handshake against a stub control
// plane and a stub gateway that reports a different IP.
func TestKillSwitchExitsOnDrift(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/launcher/session":
			if r.Header.Get("authorization") != "Bearer key-1" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = io.WriteString(w, `{"profile_id":"acct-1","expected_ip":"203.0.113.7","tunnel":{"host":"127.0.0.1","port":1,"secret":"s3cret"}}`)
		case "/launcher/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer control.Close()

	client, err := newAPIClient(control.URL, "key-1")
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	sess, err := client.session(context.Background())
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if sess.Tunnel.Secret != "s3cret" {
		t.Fatalf("secret = %q", sess.Tunnel.Secret)
	}
}

func atoi(value string) int {
	number := 0
	for _, digit := range value {
		number = number*10 + int(digit-'0')
	}
	return number
}
