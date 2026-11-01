// Package main implements `claude-box`, the customer-side launcher.
//
// The launcher is the execution plane: it does no fingerprinting of its own, it
// only makes sure the native `claude` CLI (or a desktop browser) talks to the
// internet from the exact IP the account was registered on.
//
// Contract with the rest of the system:
//
//   - `/launcher/session` requires the card key and tunnel secret, and returns
//     the profile's expected egress IP, geo and gateway address.
//   - The launcher opens a loopback CONNECT proxy. Everything the CLI sends is
//     relayed through the gateway, which enforces the domain whitelist, and from
//     there to the profile's sing-box port and its static residential upstream.
//   - Before the CLI starts, a probe confirms the egress IP really is the
//     expected one. A drift exits 1 with nothing launched, so an account never
//     appears from a foreign IP.
package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// Loopback probe budget. The CLI is useless until this passes, so it is
	// short: a residential chain that is not answering in 20s is dead.
	probeTimeout = 20 * time.Second
	// How long an idle loopback connection may sit before accept() gives up.
	dialTimeout = 15 * time.Second
	// Credentials are re-fetched when the local copy is older than this.
	credentialMaxAge = 12 * time.Hour

	defaultGatewayPort = 8443
	stateDirName       = ".claude-box"

	// reportTimeout bounds a status report; it runs after the session context
	// may already be cancelled.
	reportTimeout = 10 * time.Second
	// cooldownFloor is used when a usage-limit message carries no reset hint.
	cooldownFloor = 30 * time.Minute
)

// heartbeatEvery keeps the server-side BUSY lease alive. The control plane
// reclaims a lease after 120s of silence, so this must stay well below that.
// A var so tests can shorten it.
var heartbeatEvery = 30 * time.Second

var version = "dev"

// kernelURLDefault is baked in at build time so a customer binary works with no
// environment at all:
//
//	go build -ldflags "-X main.kernelURLDefault=https://cdn.example/kernel.tar.gz"
//
// An empty value is legal and means "ship the kernel alongside the binary"; the
// launcher then says so instead of fetching.
var kernelURLDefault = ""

// session is the subset of /launcher/session the launcher acts on.
type session struct {
	SessionID     string          `json:"session_id"`
	ProfileID     string          `json:"profile_id"`
	PlanTier      string          `json:"plan_tier"`
	OSType        string          `json:"os_type"`
	ExpectedIP    string          `json:"expected_ip"`
	ProfilePort   int             `json:"local_proxy_port"`
	NoiseSeed     int64           `json:"noise_seed"`
	Fingerprint   json.RawMessage `json:"fingerprint"`
	Geo           geoInfo         `json:"geo"`
	Tunnel        tunnel          `json:"tunnel"`
	ExpiresAt     string          `json:"expires_at"`
	HasCredential bool            `json:"has_credentials"`
}

type geoInfo struct {
	IP        string  `json:"ip"`
	Timezone  string  `json:"timezone"`
	Locale    string  `json:"locale"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Country   string  `json:"country_code"`
	City      string  `json:"city"`
}

type tunnel struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Secret string `json:"secret"`
}

func (t tunnel) addr() string {
	port := t.Port
	if port == 0 {
		port = defaultGatewayPort
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(port))
}

// fingerprintSpec mirrors the server-side profile row.
type fingerprintSpec struct {
	UserAgent string `json:"user_agent"`
	Platform  string `json:"platform"`
	Locale    string `json:"locale"`
	Screen    struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	} `json:"screen"`
	// CamoufoxConfig is the complete CAMOU_CONFIG drawn and validated at
	// profile creation. The bare kernel reads the identity from
	// CAMOU_CONFIG_1..N and knows no per-flag equivalent, so this is the only
	// way desktop mode can present the stored machine.
	CamoufoxConfig map[string]any `json:"camoufox_config"`
}

// bundle is the per-customer config shipped beside the binary. Double-clicking
// the exe is then the whole onboarding: no terminal, no flags, no memorised URL.
type bundle struct {
	Key     string `json:"key"`
	Secret  string `json:"secret"`
	Host    string `json:"host"`
	Gateway string `json:"gateway"`
	// CA is resolved against the executable's own directory.
	CA     string `json:"ca"`
	Mode   string `json:"mode"`
	Claude string `json:"claude"`
}

// loadBundle reads cce.json from the directory holding the executable.
func loadBundle() (*bundle, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(exe), "cce.json"))
	if err != nil {
		return nil, err
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("cce.json is malformed: %w", err)
	}
	if b.Key == "" || b.Secret == "" || b.Host == "" {
		return nil, errors.New("cce.json is missing key, secret or host")
	}
	if b.CA != "" && !filepath.IsAbs(b.CA) {
		b.CA = filepath.Join(filepath.Dir(exe), b.CA)
	}
	if b.Mode == "" {
		b.Mode = "cli"
	}
	return &b, nil
}

func main() {
	log.SetFlags(log.Ltime)

	// Double-clicked (no arguments): the shipped cce.json supplies everything.
	// Running it by hand with flags still works exactly as before.
	var shipped *bundle
	if len(os.Args) < 2 {
		loaded, err := loadBundle()
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-box: no arguments and no usable cce.json beside the binary: %v\n\n", err)
			usage()
			os.Exit(2)
		}
		shipped = loaded
		os.Args = append(os.Args, loaded.Mode)
		if loaded.CA != "" {
			_ = os.Setenv("CCE_TUNNEL_CA", loaded.CA)
		}
		// A double-click closes the window the moment the process ends, taking
		// any error with it. Hold it open.
		if runtime.GOOS == "windows" {
			defer func() {
				fmt.Fprint(os.Stderr, "\n按回车关闭…")
				_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
			}()
		}
	}

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	mode := os.Args[1]
	switch mode {
	case "cli", "desktop":
	case "version", "-v", "--version":
		fmt.Println(version)
		return
	default:
		usage()
		os.Exit(2)
	}

	// Parse stops at the first non-flag argument or at "--", so everything left
	// over belongs to claude. Only the two command words are re-attached below;
	// the launcher's own flags must not leak into the child.
	set := flag.NewFlagSet(mode, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	seed := func(value string, read func() string) string {
		if shipped != nil {
			return read()
		}
		return value
	}
	key := set.String("key", seed("", func() string { return shipped.Key }), "delivery card key from the order email")
	secret := set.String("secret", seed(envOr("CCE_TUNNEL_SECRET", ""), func() string { return shipped.Secret }), "delivery tunnel secret")
	host := set.String("host", seed(envOr("CCE_HOST", ""), func() string { return shipped.Host }), "control plane base URL")
	gateway := set.String("gateway", seed(envOr("CCE_GATEWAY", ""), func() string { return shipped.Gateway }), "gateway host:port override")
	claudeBin := set.String("claude", seed("claude", func() string {
		if shipped.Claude != "" {
			return shipped.Claude
		}
		return "claude"
	}), "path to the claude binary")
	runtimeDir := set.String("runtime", "", "desktop mode: directory holding the browser kernel")
	verbose := set.Bool("v", false, "verbose")
	own, claudeArgs := splitArgs(os.Args[2:], func(name string) bool {
		switch name {
		case "key", "secret", "host", "gateway", "claude", "runtime":
			return true // takes a value
		case "v":
			return false
		}
		return false
	}, func(name string) bool {
		switch name {
		case "key", "secret", "host", "gateway", "claude", "runtime", "v":
			return true
		}
		return false
	})
	if err := set.Parse(own); err != nil && !errors.Is(err, flag.ErrHelp) {
		fail("%v", err)
	}

	if *key == "" {
		fail("missing --key")
	}
	if *secret == "" {
		fail("missing --secret (or CCE_TUNNEL_SECRET)")
	}
	if *host == "" {
		fail("missing --host (or CCE_HOST)")
	}
	if *verbose {
		log.SetOutput(os.Stderr)
	} else {
		log.SetOutput(io.Discard)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := newAPIClient(*host, *key)
	if err != nil {
		fail("%v", err)
	}
	client.secret = *secret

	// A previous run may have been killed before its wipe. Clear the plaintext
	// credential directories before reserving an account, so a leftover token is
	// never mistaken for this session's (and never survives on a shared box).
	root, err := stateRoot()
	if err != nil {
		fail("%v", err)
	}
	pruneResidualCredentials(root)

	// Kill switch first: everything below assumes the account's IP is live.
	sess, err := client.session(ctx)
	if err != nil {
		fail("%v", err)
	}
	if *gateway != "" {
		host, port, splitErr := net.SplitHostPort(*gateway)
		if splitErr != nil {
			abortSession(client, ctx, statusIdle, "--gateway must be host:port: %v", splitErr)
		}
		parsed, convErr := strconv.Atoi(port)
		if convErr != nil {
			abortSession(client, ctx, statusIdle, "--gateway port is not a number: %v", convErr)
		}
		sess.Tunnel.Host, sess.Tunnel.Port = host, parsed
	}

	proxy, err := startLoopbackProxy(sess, *verbose)
	if err != nil {
		abortSession(client, ctx, statusIdle, "%v", err)
	}
	defer proxy.Close()

	// Hold the server-side lease for the whole session, not just at startup:
	// the control plane reclaims a BUSY profile after 120s without a heartbeat.
	stopBeating := keepAlive(ctx, client)
	defer stopBeating()

	observed, err := proxy.probe(ctx)
	if err != nil {
		abortSession(client, ctx, "PROXY_DEAD", "kill switch: %v", err)
	}
	if sess.ExpectedIP != "" && observed != sess.ExpectedIP {
		_ = client.heartbeat(ctx, observed)
		fail("kill switch: egress IP is %s, expected %s", observed, sess.ExpectedIP)
	}
	fmt.Fprintf(os.Stderr, "claude-box: egress verified as %s\n", observed)
	_ = client.heartbeat(ctx, observed)

	switch mode {
	case "cli":
		err = runCLI(ctx, client, sess, root, proxy, *claudeBin, claudeArgs)
	case "desktop":
		err = runDesktop(ctx, sess, root, proxy, *runtimeDir)
		client.report(ctx, outcome{status: statusIdle})
	}
	if err != nil {
		fail("%v", err)
	}
}

func abortSession(client *apiClient, ctx context.Context, state, format string, args ...any) {
	client.report(ctx, outcome{status: state})
	fail(format, args...)
}

// -- control plane ---------------------------------------------------------

type apiClient struct {
	base      string
	key       string
	sessionID string
	// secret is provisioned alongside the card key and required on every route.
	secret string
	http   *http.Client
}

func newAPIClient(host, key string) (*apiClient, error) {
	base := strings.TrimSuffix(host, "/")
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("bad --host: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("--host must be an http(s) URL")
	}
	if parsed.Scheme == "http" {
		ip := net.ParseIP(parsed.Hostname())
		if !strings.EqualFold(parsed.Hostname(), "localhost") && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("--host must use HTTPS outside loopback")
		}
	}
	// The control plane is reached directly: the tunnel is not up yet, and a
	// broken tunnel must not hide the reason we cannot start one.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &apiClient{base: base, key: key, http: &http.Client{Timeout: 30 * time.Second, Transport: transport}}, nil
}

func (c *apiClient) do(ctx context.Context, method, path, secret string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("authorization", "Bearer "+c.key)
	if secret != "" {
		request.Header.Set("x-tunnel-secret", secret)
	}
	if c.sessionID != "" {
		request.Header.Set("x-session-id", c.sessionID)
	}
	return c.http.Do(request)
}

func (c *apiClient) session(ctx context.Context) (*session, error) {
	// Both delivery credentials are required before a profile is reserved.
	resp, err := c.do(ctx, http.MethodPost, "/launcher/session", c.secret)
	if err != nil {
		return nil, fmt.Errorf("contacting control plane: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane refused the key (%s): %s", resp.Status, firstLine(body))
	}
	var sess session
	if err := json.Unmarshal(body, &sess); err != nil {
		return nil, fmt.Errorf("malformed session payload: %w", err)
	}
	if sess.ProfileID == "" || sess.SessionID == "" || sess.Tunnel.Host == "" {
		return nil, errors.New("session payload incomplete")
	}
	sess.Tunnel.Secret = c.secret
	c.sessionID = sess.SessionID
	return &sess, nil
}

func (c *apiClient) credentials(ctx context.Context, secret string) ([]byte, error) {
	resp, err := c.do(ctx, http.MethodGet, "/launcher/credentials", secret)
	if err != nil {
		return nil, fmt.Errorf("fetching credentials: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("credentials refused (%s): %s", resp.Status, firstLine(body))
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func (c *apiClient) heartbeat(ctx context.Context, observed string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/launcher/heartbeat", nil)
	if err != nil {
		return err
	}
	request.Header.Set("authorization", "Bearer "+c.key)
	request.Header.Set("x-tunnel-secret", c.secret)
	request.Header.Set("x-session-id", c.sessionID)
	request.Header.Set("x-observed-ip", observed)
	resp, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// credentialFailure reports the vocabulary the control plane's state machine
// understands. Anything else is refused there, so the two must stay in step.
const (
	statusAuthExpired = "AUTH_EXPIRED"
	statusCooldown    = "COOLDOWN"
	statusIdle        = "IDLE"
)

// reportStatus tells the control plane how the session ended.
//
// The gateway is a blind TLS splice: it never sees the HTTP status inside the
// tunnel, so an expired token or a hit usage limit is invisible to the server
// unless the launcher — the only party that sees the CLI's exit — says so. The
// report is best-effort: a session that ran fine is not failed because the
// network dropped while filing the paperwork.
func (c *apiClient) reportStatus(ctx context.Context, state, reason string, cooldown time.Duration) error {
	payload := map[string]any{"status": state}
	if reason != "" {
		payload["reason"] = truncate(reason, 190)
	}
	if cooldown > 0 {
		payload["cooldown_seconds"] = int(cooldown.Seconds())
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// The session context may already be cancelled by the time we report, so
	// the report gets its own deadline.
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(reportCtx, http.MethodPost, c.base+"/launcher/status", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("authorization", "Bearer "+c.key)
	request.Header.Set("x-tunnel-secret", c.secret)
	request.Header.Set("x-session-id", c.sessionID)
	request.Header.Set("content-type", "application/json")

	resp, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("status report refused: %s", resp.Status)
	}
	return nil
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

// -- loopback proxy --------------------------------------------------------

// loopback is the local CONNECT proxy the CLI is pointed at.
//
// It exists so the CLI needs no awareness of the tunnel: it signs each CONNECT
// with the tunnel secret and hands the socket to the gateway, which applies the
// domain whitelist.
type loopback struct {
	listener net.Listener
	target   string
	secret   string
	profile  int
	verbose  bool
	closed   chan struct{}
	once     sync.Once
}

func startLoopbackProxy(sess *session, verbose bool) (*loopback, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("cannot bind loopback proxy: %w", err)
	}
	p := &loopback{
		listener: listener,
		target:   sess.Tunnel.addr(),
		secret:   sess.Tunnel.Secret,
		profile:  sess.ProfilePort,
		verbose:  verbose,
		closed:   make(chan struct{}),
	}
	go p.serve()
	return p, nil
}

func (p *loopback) addr() string { return p.listener.Addr().String() }

func (p *loopback) URL() string { return "http://" + p.addr() }

func (p *loopback) Close() {
	p.once.Do(func() {
		close(p.closed)
		_ = p.listener.Close()
	})
}

func (p *loopback) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
			}
			continue
		}
		go p.handle(conn)
	}
}

func (p *loopback) handle(local net.Conn) {
	defer local.Close()
	_ = local.SetDeadline(time.Now().Add(dialTimeout))

	upstream, err := tls.Dial("tcp", p.target, tunnelTLSConfig(p.target))
	if err != nil {
		p.trace("tunnel dial %s: %v", p.target, err)
		return
	}
	defer upstream.Close()

	// The gateway reads an HTTP CONNECT with our credentials before it will
	// splice, whichever protocol the client spoke to us.
	head, err := readHead(local)
	if err != nil {
		return
	}
	request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\n",
		head, head, p.secret)
	if p.profile > 0 {
		// Which residential exit to use. The gateway refuses traffic without it
		// from its own IP, which the kill switch would flag right after.
		request += "x-profile-port: " + strconv.Itoa(p.profile) + "\r\n"
	}
	if _, err := io.WriteString(upstream, request+"\r\n"); err != nil {
		return
	}
	if !p.awaitEstablished(upstream) {
		_, _ = io.WriteString(local, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	_, _ = io.WriteString(local, "HTTP/1.1 200 Connection Established\r\n\r\n")

	_ = local.SetDeadline(time.Time{})
	_ = upstream.SetDeadline(time.Time{})
	pipe(local, upstream)
}

// tunnelTLSConfig verifies the gateway by name. `CCE_TUNNEL_CA` adds a private
// CA (self-hosted gateways, and local runs against a test certificate).
func tunnelTLSConfig(target string) *tls.Config {
	config := &tls.Config{
		ServerName: strings.Split(target, ":")[0],
		MinVersion: tls.VersionTLS12,
	}
	path := os.Getenv("CCE_TUNNEL_CA")
	if path == "" {
		return config
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		log.Printf("CCE_TUNNEL_CA %s: %v", path, err)
		return config
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		log.Printf("CCE_TUNNEL_CA %s: no certificates found", path)
		return config
	}
	config.RootCAs = pool
	return config
}

// awaitEstablished swallows the gateway's response head and reports whether the
// tunnel was accepted.
func (p *loopback) awaitEstablished(upstream net.Conn) bool {
	_ = upstream.SetDeadline(time.Now().Add(dialTimeout))
	reader := make([]byte, 0, 128)
	buf := make([]byte, 1)
	for len(reader) < 512 {
		if _, err := upstream.Read(buf); err != nil {
			return false
		}
		reader = append(reader, buf[0])
		if bytes.HasSuffix(reader, []byte("\r\n\r\n")) {
			break
		}
	}
	status := strings.SplitN(string(reader), "\r\n", 2)[0]
	ok := strings.Contains(status, " 200")
	if !ok {
		p.trace("tunnel rejected: %s", status)
	}
	return ok
}

// probe asks for the egress IP through the tunnel, using the same path the CLI
// will use, so a broken chain fails here rather than mid-session.
func (p *loopback) probe(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	transport := &http.Transport{
		Proxy:               func(*http.Request) (*url.URL, error) { return url.Parse(p.URL()) },
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: probeTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: probeTimeout}

	// Both endpoints are on the gateway whitelist, so a rejection here really is
	// a dead chain and not a blocked host. ip-api answers over plain HTTP, which
	// also covers a chain that broke TLS.
	for _, endpoint := range []string{"https://ipinfo.io/ip", "http://ip-api.com/line/?fields=query"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(request)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		if ip := strings.TrimSpace(string(body)); net.ParseIP(ip) != nil {
			return ip, nil
		}
	}
	return "", errors.New("cannot read egress IP through the tunnel (proxy dead, or IP drift)")
}

func (p *loopback) trace(format string, args ...any) {
	if p.verbose {
		log.Printf("proxy: "+format, args...)
	}
}

// -- cli mode --------------------------------------------------------------

// findClaude resolves the CLI. A bare name goes through PATH, but a customer
// who dropped `claude.exe` next to the launcher should not need to touch PATH
// at all, so the executable's own directory is searched first.
func findClaude(want string) (string, error) {
	if strings.ContainsRune(want, os.PathSeparator) || strings.Contains(want, "/") {
		return want, nil
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for _, name := range []string{want, want + ".exe", want + ".bat", want + ".cmd"} {
			candidate := filepath.Join(dir, name)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
		}
	}
	return exec.LookPath(want)
}

func runCLI(ctx context.Context, client *apiClient, sess *session, root string, proxy *loopback, claudeBin string, claudeArgs []string) error {
	reported := false
	defer func() {
		if !reported {
			client.report(ctx, outcome{status: statusIdle})
		}
	}()
	configDir := filepath.Join(root, "profiles", sess.ProfileID, ".claude")
	if err := refreshCredentials(ctx, client, sess, configDir); err != nil {
		return err
	}
	// The account's tokens exist only for this session; a stale plaintext copy
	// on a shared machine is a liability, so the wipe is unconditional. The
	// deferred removal also runs on Ctrl-C, because exec.CommandContext only
	// kills the child and runCLI still returns normally.
	defer func() { _ = os.RemoveAll(filepath.Join(root, "profiles", sess.ProfileID)) }()

	binary, err := findClaude(claudeBin)
	if err != nil {
		return fmt.Errorf("claude binary not found (%s); install the Claude CLI first", claudeBin)
	}

	tail := &tailBuffer{limit: 4096}

	cmd := exec.CommandContext(ctx, binary, claudeArgs...)
	cmd.Stdin, cmd.Stdout = os.Stdin, os.Stdout
	// The CLI still writes to the console, but stderr is teed so the exit can
	// be classified afterwards.
	cmd.Stderr = io.MultiWriter(os.Stderr, tail)
	cmd.Env = append(os.Environ(),
		"CLAUDE_CONFIG_DIR="+configDir,
		"HTTPS_PROXY="+proxy.URL(),
		"HTTP_PROXY="+proxy.URL(),
		"https_proxy="+proxy.URL(),
		"http_proxy="+proxy.URL(),
		"TZ="+firstNonEmpty(sess.Geo.Timezone, "UTC"),
		"NO_PROXY=localhost,127.0.0.1",
	)
	runErr := cmd.Run()
	var exitErr *exec.ExitError
	code := 0
	if errors.As(runErr, &exitErr) {
		code = exitErr.ExitCode()
		runErr = nil
	} else if runErr != nil {
		code = -1
	}
	result := classifyRun(code, tail.String())
	client.report(ctx, result)
	reported = result.status != ""
	return runErr
}

// outcome is one launcher judgement about a finished session.
type outcome struct {
	status string
	reason string
	// cooldown is sent only for a usage-limit hit, and scaled by plan tier:
	// a 20x account that hits its cap needs hours, not minutes.
	cooldown time.Duration
}

func (c *apiClient) report(ctx context.Context, result outcome) {
	if result.status == "" || c.secret == "" {
		return
	}
	if err := c.reportStatus(ctx, result.status, result.reason, result.cooldown); err != nil {
		log.Printf("warning: could not report session status: %v", err)
	}
}

// classifyRun turns an exit code and the tail of stderr into a status.
//
// The CLI signals an expired or rejected token with the HTTP status in the
// message, and a hit usage limit with a 429. A bare Ctrl-C is not a fault and
// must not park the account. Unknown failures stay silent rather than guessing:
// a wrong COOLDOWN costs the fleet more than a missing one.
func classifyRun(code int, stderr string) outcome {
	haystack := strings.ToLower(stderr)
	switch {
	case isUsageLimit(haystack):
		return outcome{status: statusCooldown, reason: "usage limit", cooldown: cooldownFromLimit(stderr)}
	case isAuthFailure(haystack):
		return outcome{status: statusAuthExpired, reason: firstLineOf(stderr)}
	case code == 0:
		return outcome{status: statusIdle}
	case code == 130 || code == -1:
		// Interrupted or never started: nothing to conclude.
		return outcome{}
	case isProxyFailure(haystack):
		return outcome{status: "PROXY_DEAD", reason: firstLineOf(stderr)}
	default:
		return outcome{}
	}
}

func isAuthFailure(lower string) bool {
	markers := []string{
		"401", "403", "unauthorized", "invalid_api_key", "invalid api key",
		"authentication_error", "authentication failed", "please log in",
		"not logged in", "logged out", "token expired", "invalid_grant",
		"oauth token has been revoked", "credit balance is too low",
	}
	return containsAny(lower, markers)
}

func isUsageLimit(lower string) bool {
	markers := []string{"429", "usage limit", "rate limit", "rate_limit_error",
		"too many requests", "reached your limit", "limit reached"}
	return containsAny(lower, markers)
}

func isProxyFailure(lower string) bool {
	markers := []string{"proxyconnect", "connection refused", "econnrefused",
		"proxy unreachable", "tunnel secret", "cannot read egress ip"}
	return containsAny(lower, markers)
}

func containsAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

// cooldownFromLimit reads a "resets at 3pm" / "try again in 4h" hint and
// falls back to the floor. The value is clamped by the control plane too.
func cooldownFromLimit(stderr string) time.Duration {

	re := regexp.MustCompile(`(?i)(?:try again in|resets in|retry in)\s+(\d+)\s*(second|minute|hour|day)s?`)
	hit := re.FindStringSubmatch(stderr)
	if hit == nil {
		return cooldownFloor
	}
	count, err := strconv.Atoi(hit[1])
	if err != nil || count <= 0 {
		return cooldownFloor
	}
	unit := map[string]time.Duration{
		"second": time.Second, "minute": time.Minute,
		"hour": time.Hour, "day": 24 * time.Hour,
	}[strings.ToLower(hit[2])]
	return time.Duration(count) * unit
}

func firstLineOf(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return truncate(trimmed, 190)
		}
	}
	return ""
}

// tailBuffer keeps the last `limit` bytes written to it.
type tailBuffer struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func (t *tailBuffer) Write(chunk []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = append(t.data, chunk...)
	if len(t.data) > t.limit {
		// Keep the tail only: the reason is printed just before the exit.
		t.data = t.data[len(t.data)-t.limit:]
	}
	return len(chunk), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.data)
}

// keepAlive heartbeats the control plane until the returned stop function is
// called, so the server-side BUSY lease does not expire during a long session.
func keepAlive(ctx context.Context, client *apiClient) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(heartbeatEvery)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				// A stop that already happened wins over a tick that is only
				// now being delivered, so the count is final once stop returns.
				select {
				case <-done:
					return
				default:
				}
				beatCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reportTimeout)
				if err := client.heartbeat(beatCtx, ""); err != nil {
					log.Printf("warning: heartbeat failed: %v", err)
				}
				cancel()
			}
		}
	}()
	return func() { close(done) }
}

// pruneResidualCredentials removes plaintext credential directories a previous
// run left behind (kill -9, power loss, or a crash before the deferred wipe).
//
// Only `.claude` and its `.incoming` staging sibling are cleared; a desktop
// profile keeps its `browser_data` because that is meant to persist. A
// credential file touched within `heartbeatEvery` is treated as a session
// running in another terminal and left alone, so starting one account does not
// pull the config dir out from under a concurrent one.
func pruneResidualCredentials(root string) {
	profilesDir := filepath.Join(root, "profiles")
	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(profilesDir, entry.Name())
		configDir := filepath.Join(dir, ".claude")
		if stamp, err := os.Stat(filepath.Join(configDir, ".credentials.json")); err == nil &&
			time.Since(stamp.ModTime()) < heartbeatEvery {
			continue
		}
		_ = os.RemoveAll(configDir)
		_ = os.RemoveAll(configDir + ".incoming")
		if rest, err := os.ReadDir(dir); err == nil && len(rest) == 0 {
			_ = os.Remove(dir)
		}
	}
}

// refreshCredentials downloads and unpacks the encrypted credential archive
// unless the local copy is still fresh.
func refreshCredentials(ctx context.Context, client *apiClient, sess *session, configDir string) error {
	if stamp, err := os.Stat(filepath.Join(configDir, ".credentials.json")); err == nil {
		if time.Since(stamp.ModTime()) < credentialMaxAge {
			return nil
		}
	}
	archive, err := client.credentials(ctx, sess.Tunnel.Secret)
	if err != nil {
		return err
	}
	// Unpack beside the live directory and swap, so an interrupted extraction
	// cannot leave claude reading half a config store.
	staging := configDir + ".incoming"
	_ = os.RemoveAll(staging)
	if err := extractTarGz(archive, staging); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	_ = os.RemoveAll(configDir)
	if err := os.Rename(filepath.Join(staging, ".claude"), configDir); err != nil {
		_ = os.RemoveAll(staging)
		return err
	}
	return os.RemoveAll(staging)
}

// extractTarGz unpacks an archive whose entries are rooted at `.claude`.
func extractTarGz(archive []byte, destDir string) error {
	reader, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return fmt.Errorf("credentials are not gzip: %w", err)
	}
	defer reader.Close()
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return err
	}

	tarReader := tar.NewReader(reader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		// Guard against traversal: the archive comes over the network.
		clean := filepath.Clean(header.Name)
		if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
			continue
		}
		path := filepath.Join(destDir, clean)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, io.LimitReader(tarReader, 8<<20)); err != nil {
				file.Close()
				return err
			}
			file.Close()
		}
	}
}

// -- desktop mode ----------------------------------------------------------

func runDesktop(ctx context.Context, sess *session, root string, proxy *loopback, runtimeDir string) error {
	runtimePath := runtimeDir
	if runtimePath == "" {
		runtimePath = filepath.Join(root, "runtime")
	}
	binary, err := ensureKernel(runtimePath)
	if err != nil {
		return err
	}
	userDataDir := filepath.Join(root, "profiles", sess.ProfileID, "browser_data")
	if err := os.MkdirAll(userDataDir, 0o700); err != nil {
		return err
	}
	stripQuarantine(runtimePath)

	env, err := camoufoxEnv(sess, runtimePath, proxy)
	if err != nil {
		return err
	}
	// The kernel takes the identity from the environment and the profile from
	// a flag; `--fingerprint`/`--timezone`/`--lang` are not kernel flags.
	args := []string{"-profile", userDataDir, "-no-remote"}
	// A hosted box has no display; the same binary still has to run there.
	if os.Getenv("CCE_HEADLESS") != "" {
		args = append(args, "-headless")
	}
	args = append(args, "https://claude.ai")
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout, cmd.Stderr = io.Discard, os.Stderr
	cmd.Env = append(env, "TZ="+firstNonEmpty(sess.Geo.Timezone, "UTC"))
	return cmd.Run()
}

// camoufoxEnv builds the environment a bare Camoufox kernel needs: the stored
// identity as CAMOU_CONFIG (plus the live geo that must follow the exit node),
// the proxy prefs, and -- on Linux -- a fontconfig that resolves the bundle's
// fonts absolutely. This mirrors what camoufox's own launcher does; skipping
// any part means the browser presents a different machine than the profile.
func camoufoxEnv(sess *session, runtimePath string, proxy *loopback) ([]string, error) {
	spec := parseFingerprint(sess.Fingerprint)
	config := make(map[string]any, len(spec.CamoufoxConfig)+6)
	for key, value := range spec.CamoufoxConfig {
		config[key] = value
	}

	// The drawing is pinned; the exit node is not. Timezone, locale, geo
	// coordinates and the WebRTC address all have to follow the live IP or the
	// identity contradicts the tunnel.
	if geo := sess.Geo; geo.Timezone != "" || geo.IP != "" || geo.Locale != "" {
		if geo.Timezone != "" {
			config["timezone"] = geo.Timezone
		}
		if geo.IP != "" {
			config["webrtc:ipv4"] = geo.IP
		}
		if geo.Latitude != 0 || geo.Longitude != 0 {
			config["geolocation:latitude"] = geo.Latitude
			config["geolocation:longitude"] = geo.Longitude
		}
		locale := firstNonEmpty(geo.Locale, spec.Locale)
		if locale != "" {
			language, region, _ := strings.Cut(locale, "-")
			config["locale:language"] = language
			if region != "" {
				config["locale:region"] = region
			}
		}
	}

	host, portText, err := net.SplitHostPort(proxy.addr())
	if err != nil {
		return nil, fmt.Errorf("loopback address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil, err
	}
	// Everything goes through the loopback proxy, which is the only path the
	// kill switch can vouch for.
	prefs := map[string]any{
		"network.proxy.type":                      1,
		"network.proxy.http":                      host,
		"network.proxy.http_port":                 port,
		"network.proxy.ssl":                       host,
		"network.proxy.ssl_port":                  port,
		"network.proxy.share_proxy_settings":      true,
		"network.proxy.allow_hijacking_localhost": true,
		// A private gateway CA reaches the browser through the OS store, which
		// Firefox ignores unless enterprise roots are on.
		"security.enterprise_roots.enabled": true,
	}
	// Escape hatch for operators: a JSON object of extra prefs (e.g. a proxy
	// exemption or an h2 toggle for a deployment whose middleboxes need it).
	if raw := os.Getenv("CCE_EXTRA_PREFS"); raw != "" {
		var extra map[string]any
		if err := json.Unmarshal([]byte(raw), &extra); err != nil {
			return nil, fmt.Errorf("CCE_EXTRA_PREFS is not JSON: %w", err)
		}
		for key, value := range extra {
			prefs[key] = value
		}
	}
	// The browser's own UI language has to agree with the Intl locale; without
	// it a fr-FR page still shows English validation messages.
	if language, ok := config["locale:language"].(string); ok && language != "" {
		requested := language
		if region, ok := config["locale:region"].(string); ok && region != "" {
			requested += "-" + region
		}
		prefs["intl.locale.requested"] = requested
	}

	env := os.Environ()
	configEnv, err := chunkEnv("CAMOU_CONFIG_", config)
	if err != nil {
		return nil, err
	}
	prefEnv, err := chunkEnv("CAMOU_PREFS_", prefs)
	if err != nil {
		return nil, err
	}
	env = append(env, configEnv...)
	env = append(env, prefEnv...)

	if runtime.GOOS == "linux" {
		if conf, err := fontConfigFile(runtimePath, sess.OSType); err != nil {
			log.Printf("fontconfig unavailable: %v", err)
		} else if conf != "" {
			env = append(env, "FONTCONFIG_FILE="+conf)
		}
	}
	return env, nil
}

// chunkEnv serialises a map into `prefix1..N` variables. The kernel concatenates
// them before parsing, and the environment block has a hard size limit, so the
// split is mandatory rather than cosmetic: 2047 on Windows (ANSI conversion),
// 32767 elsewhere.
func chunkEnv(prefix string, value map[string]any) ([]string, error) {
	raw, err := asciiJSON(value)
	if err != nil {
		return nil, err
	}
	size := 32767
	if runtime.GOOS == "windows" {
		size = 2047
	}
	var env []string
	for i := 0; i < len(raw); i += size {
		end := i + size
		if end > len(raw) {
			end = len(raw)
		}
		env = append(env, fmt.Sprintf("%s%d=%s", prefix, i/size+1, raw[i:end]))
	}
	return env, nil
}

// asciiJSON encodes escapes only, because Windows reads the environment through
// the ANSI code page and mangles raw UTF-8; JSON.parse restores the escapes.
func asciiJSON(value map[string]any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	out.Grow(len(raw))
	for _, r := range string(raw) {
		if r < 0x80 {
			out.WriteRune(r)
			continue
		}
		if r > 0xFFFF {
			r -= 0x10000
			fmt.Fprintf(&out, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
			continue
		}
		fmt.Fprintf(&out, `\u%04x`, r)
	}
	return out.String(), nil
}

// fontConfigFile renders the bundle's fontconfig with absolute font paths. The
// shipped file uses prefix="cwd", which breaks as soon as the working directory
// is not the bundle: fontconfig then finds no fonts at all.
func fontConfigFile(runtimePath, osType string) (string, error) {
	source := filepath.Join(runtimePath, "fontconfig", osDirName(osType), "fonts.conf")
	body, err := os.ReadFile(source)
	if err != nil {
		return "", err
	}
	fontsDir := filepath.Join(runtimePath, "fonts")
	var dirs []string
	if groups, err := os.ReadFile(filepath.Join(fontsDir, "groups.json")); err == nil {
		var parsed struct {
			ReadBy map[string][]string `json:"readBy"`
		}
		if json.Unmarshal(groups, &parsed) == nil {
			// fontconfig scans recursively, so only the groups this OS reads
			// are listed -- otherwise another OS's faces become fallback
			// candidates.
			for _, group := range parsed.ReadBy[osTriple(osType)] {
				candidate := filepath.Join(fontsDir, group)
				if info, err := os.Stat(candidate); err == nil && info.IsDir() {
					dirs = append(dirs, candidate)
				}
			}
		}
	}
	if len(dirs) == 0 {
		if info, err := os.Stat(filepath.Join(fontsDir, osDirName(osType))); err == nil && info.IsDir() {
			dirs = []string{filepath.Join(fontsDir, osDirName(osType))}
		} else {
			dirs = []string{fontsDir}
		}
	}
	var rendered strings.Builder
	for _, dir := range dirs {
		rendered.WriteString("\t<dir>" + dir + "</dir>\n")
	}
	patched := strings.Replace(string(body), `<dir prefix="cwd">fonts</dir>`, rendered.String(), 1)

	// A content hash keeps the file pure-cache: it is regenerated only when the
	// bundle or the patch changes, and never written into the bundle itself
	// (which may be root-owned and read-only).
	sum := sha256.Sum256([]byte(patched))
	confDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	confDir = filepath.Join(confDir, "claude-box", "fontconfig")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		return "", err
	}
	target := filepath.Join(confDir, fmt.Sprintf("fonts-%x.conf", sum[:6]))
	if err := os.WriteFile(target, []byte(patched), 0o600); err != nil {
		return "", err
	}
	return target, nil
}

// osDirName is the bundle's directory spelling, osTriple the font group key.
func osDirName(osType string) string {
	switch osType {
	case "windows":
		return "windows"
	case "macos":
		return "macos"
	}
	return "linux"
}

func osTriple(osType string) string {
	switch osType {
	case "windows":
		return "win"
	case "macos":
		return "mac"
	}
	return "lin"
}

// ensureKernel returns a usable browser binary from runtimeDir, downloading a
// pinned archive when the directory is empty.
func ensureKernel(runtimeDir string) (string, error) {
	binary := kernelBinaryName()
	path := filepath.Join(runtimeDir, binary)
	if hasKernel(runtimeDir) {
		return path, nil
	}

	source := envOr("CCE_KERNEL_URL", kernelURLDefault)
	if source == "" {
		return "", fmt.Errorf("browser kernel missing in %s (set CCE_KERNEL_URL, or build with -X main.kernelURLDefault=...)", runtimeDir)
	}
	log.Printf("downloading browser kernel from %s", source)
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return "", err
	}
	if err := download(source, path); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return "", err
	}
	return path, nil
}

func kernelBinaryName() string {
	switch runtime.GOOS {
	case "windows":
		return "camoufox.exe"
	case "darwin":
		return "Camoufox.app/Contents/MacOS/camoufox"
	default:
		return "camoufox"
	}
}

// hasKernel reports whether a runtime directory already holds a launchable
// kernel -- both the binary and the settings Camoufox reads from beside it.
func hasKernel(runtimeDir string) bool {
	binary := filepath.Join(runtimeDir, kernelBinaryName())
	if info, err := os.Stat(binary); err != nil || info.IsDir() {
		return false
	}
	_, err := os.Stat(filepath.Join(runtimeDir, "properties.json"))
	return err == nil
}

func download(source, path string) error {
	scheme := "file://"
	if strings.HasPrefix(source, scheme) {
		return copyFile(strings.TrimPrefix(source, scheme), path)
	}
	resp, err := http.Get(source)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("kernel download failed: %s", resp.Status)
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(file, resp.Body)
	return err
}

func copyFile(source, dest string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// stripQuarantine removes the macOS Gatekeeper flag, otherwise a freshly
// downloaded kernel is blocked by a modal the user cannot click through when
// the browser is started non-interactively.
func stripQuarantine(path string) {
	if runtime.GOOS != "darwin" {
		return
	}
	if err := exec.Command("xattr", "-rd", "com.apple.quarantine", path).Run(); err != nil {
		log.Printf("xattr quarantine removal failed: %v", err)
	}
}

// -- helpers ---------------------------------------------------------------

// readHead consumes the client's whole request head and returns the CONNECT
// target.
//
// Draining all of it matters: the client's remaining header lines would
// otherwise be spliced into the tunnel *after* the gateway answered, and the
// origin would see them as the start of a TLS handshake.
func readHead(conn net.Conn) (string, error) {
	head := make([]byte, 0, 512)
	chunk := make([]byte, 1)
	for len(head) < 8192 {
		if _, err := conn.Read(chunk); err != nil {
			return "", err
		}
		head = append(head, chunk[0])
		if bytes.HasSuffix(head, []byte("\r\n\r\n")) {
			break
		}
	}
	line, _, _ := strings.Cut(string(head), "\r\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "CONNECT") {
		return "", errors.New("expected a CONNECT request")
	}
	target := fields[1]
	if !strings.Contains(target, ":") {
		target += ":443"
	}
	return target, nil
}

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}
	go pump(a, b)
	go pump(b, a)
	wg.Wait()
}

// splitArgs separates the launcher's flags from the child's arguments.
//
// The child's own flags look exactly like ours (`claude --resume`), and Go's
// flag package only stops at the first non-flag token, so a hand-rolled split is
// needed: scanning stops at the first token that is not one of our flags, or at
// an explicit `--`.
func splitArgs(args []string, takesValue, known func(string) bool) (own, rest []string) {
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			return own, args[index+1:]
		}
		name := strings.TrimLeft(arg, "-")
		if !strings.HasPrefix(arg, "-") || !known(name) {
			return own, args[index:]
		}
		own = append(own, arg)
		if takesValue(name) && index+1 < len(args) {
			index++
			own = append(own, args[index])
		}
	}
	return own, rest
}

// stateRoot is ~/.claude-box, created on demand.
func stateRoot() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	root := filepath.Join(home, stateDirName)
	return root, os.MkdirAll(root, 0o700)
}

func parseFingerprint(raw json.RawMessage) fingerprintSpec {
	var spec fingerprintSpec
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &spec)
	}
	return spec
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func firstLine(body []byte) string {
	text := strings.TrimSpace(string(body))
	if index := strings.IndexByte(text, '\n'); index >= 0 {
		text = text[:index]
	}
	if len(text) > 300 {
		text = text[:300]
	}
	return text
}

func usage() {
	fmt.Fprint(os.Stderr, `claude-box `+version+`

  claude-box cli     --key <CARD_KEY> --secret <TUNNEL_SECRET> --host <URL> [-- <claude args>]
  claude-box desktop --key <CARD_KEY> --secret <TUNNEL_SECRET> --host <URL> [--runtime <dir>]

Both modes verify the egress IP before handing over to the client. The decrypted
Claude credential directory is always erased on exit; the next start clears any
copy a killed run left behind.

Environment:
  CCE_HOST          default for --host
  CCE_TUNNEL_SECRET default for --secret
  CCE_GATEWAY       gateway host:port override
  CCE_TUNNEL_CA     PEM bundle to trust for the gateway (self-hosted/pinned)
  CCE_KERNEL_URL    where desktop mode fetches the browser kernel (baked-in
                    default applies when the binary was built with one)
  CCE_HEADLESS      run desktop mode without a display (hosted boxes)
  CCE_EXTRA_PREFS   JSON object of extra Firefox prefs for desktop mode
  CCE_TUNNEL_CERT   gateway certificate (server side, same variable name)
`)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "claude-box: "+format+"\n", args...)
	os.Exit(1)
}

// digest is used by tests to fingerprint a session payload.
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:8])
}

var _ = digest
var _ = httputil.DumpRequestOut
var _ = rand.Reader
