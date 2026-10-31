// Package e2e runs unmodified upstream frps and frpc locally, with WSS
// terminated by a TLS reverse proxy, the way Bunny CDN terminates it in front
// of the relay container.
//
// Binaries are taken from FRP_BIN_DIR (default ../.bin). The tests are skipped
// when the binaries are missing.
package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const token = "test-token-0123456789abcdef0123456789"

func binDir(t *testing.T) string {
	dir := os.Getenv("FRP_BIN_DIR")
	if dir == "" {
		dir = "../.bin"
	}
	if _, err := os.Stat(filepath.Join(dir, "frps")); err != nil {
		t.Skipf("frp binaries not found in %s (set FRP_BIN_DIR)", dir)
	}
	return dir
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func start(t *testing.T, name string, env []string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	var log bytes.Buffer
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("%s output:\n%s", filepath.Base(name), log.String())
		}
	})
	return cmd
}

type relay struct {
	vhost   string // http://127.0.0.1:<vhostHTTPPort>
	wssPort int    // TLS front door that proxies to frps bindPort
	caFile  string // CA that signed the front door certificate
	direct  int    // frps bindPort, as reached through Anycast
}

// startRelay runs frps with the real relay config (ports rewritten) behind a
// TLS-terminating reverse proxy.
func startRelay(t *testing.T, bin string, env ...string) relay {
	dir := t.TempDir()
	bindPort, vhostPort := freePort(t), freePort(t)
	cfg, err := os.ReadFile("../relay/frps.toml")
	if err != nil {
		t.Fatal(err)
	}
	local := strings.NewReplacer("bindPort = 7000", fmt.Sprintf("bindPort = %d", bindPort),
		"vhostHTTPPort = 8080", fmt.Sprintf("vhostHTTPPort = %d", vhostPort)).Replace(string(cfg))
	path := filepath.Join(dir, "frps.toml")
	if err := os.WriteFile(path, []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	start(t, filepath.Join(bin, "frps"), append([]string{"NORDRAY_TUNNEL_TOKEN=" + token, "NORDRAY_LOG_LEVEL=info"}, env...), "-c", path)

	backend, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", bindPort))
	front := httptest.NewUnstartedServer(httputil.NewSingleHostReverseProxy(backend))
	wssPort := freePort(t)
	front.Listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", wssPort))
	if err != nil {
		t.Fatal(err)
	}
	front.StartTLS()
	t.Cleanup(front.Close)

	caFile := filepath.Join(dir, "ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw})
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	waitListening(t, bindPort)
	return relay{vhost: fmt.Sprintf("http://127.0.0.1:%d", vhostPort), wssPort: wssPort, caFile: caFile, direct: bindPort}
}

func waitListening(t *testing.T, port int) {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			c.Close()
			return
		}
	}
	t.Fatalf("port %d not listening", port)
}

type proxy struct {
	name, domain string
	localPort    int
}

// writeFrpc writes the frpc config shape the CLI is meant to generate.
// tlsLines lets tests vary the trust settings.
func writeFrpc(t *testing.T, r relay, tok, tlsLines string, proxies ...proxy) string {
	return writeFrpcTo(t, r.wssPort, "wss", tok, tlsLines, proxies...)
}

func writeFrpcTo(t *testing.T, port int, protocol, tok, tlsLines string, proxies ...proxy) string {
	var b strings.Builder
	fmt.Fprintf(&b, "serverAddr = \"127.0.0.1\"\nserverPort = %d\nloginFailExit = true\n", port)
	fmt.Fprintf(&b, "auth.method = \"token\"\nauth.token = %q\n", tok)
	fmt.Fprintf(&b, "transport.protocol = %q\n%s\n", protocol, tlsLines)
	for _, p := range proxies {
		fmt.Fprintf(&b, "[[proxies]]\nname = %q\ntype = \"http\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %d\ncustomDomains = [%q]\n\n",
			p.name, p.localPort, p.domain)
	}
	path := filepath.Join(t.TempDir(), "frpc.toml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func expectLoginFailureOutput(t *testing.T, bin, cfg string) string {
	cmd := exec.Command(filepath.Join(bin, "frpc"), "-c", cfg)
	timer := time.AfterFunc(20*time.Second, func() { _ = cmd.Process.Kill() })
	defer timer.Stop()
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("frpc unexpectedly succeeded:\n%s", out)
	}
	return string(out)
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	return lines[len(lines)-1]
}

// The front door certificate from httptest is issued for example.com.
func trusted(r relay) string {
	return fmt.Sprintf("transport.tls.trustedCaFile = %q\ntransport.tls.serverName = \"example.com\"", r.caFile)
}

// fixture identifies itself, echoes request bodies and serves sized downloads.
func fixture(t *testing.T, id string) int {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			h := sha256.New()
			n, _ := io.Copy(h, r.Body)
			fmt.Fprintf(w, "%s %d %x", id, n, h.Sum(nil))
		case r.URL.Path == "/big":
			_, _ = io.CopyN(w, zeroReader{}, 32<<20)
		default:
			fmt.Fprintf(w, "%s host=%s auth=%q", id, r.Host, r.Header.Get("Authorization"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func get(t *testing.T, r relay, host, path string) (int, string) {
	req, _ := http.NewRequest(http.MethodGet, r.vhost+path, nil)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// waitRoute polls until host is routed or the deadline passes.
func waitRoute(t *testing.T, r relay, host string) {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if code, _ := get(t, r, host, "/"); code == http.StatusOK {
			return
		}
	}
	t.Fatalf("route for %s never became ready", host)
}

// expectLoginFailure runs frpc with loginFailExit and expects a non-zero exit.
func expectLoginFailure(t *testing.T, bin, cfg, wantLog string) {
	out := expectLoginFailureOutput(t, bin, cfg)
	if !strings.Contains(out, wantLog) {
		t.Fatalf("frpc output lacks %q:\n%s", wantLog, out)
	}
}

func TestWSSRoundTrip(t *testing.T) {
	bin := binDir(t)
	r := startRelay(t, bin)
	a, b := fixture(t, "app-a"), fixture(t, "app-b")
	cfg := writeFrpc(t, r, token, trusted(r),
		proxy{"a", "a.example.test", a}, proxy{"b", "b.example.test", b})
	start(t, filepath.Join(bin, "frpc"), nil, "-c", cfg)
	waitRoute(t, r, "a.example.test")
	waitRoute(t, r, "b.example.test")

	t.Run("routes by host without cross-routing", func(t *testing.T) {
		for host, want := range map[string]string{"a.example.test": "app-a", "b.example.test": "app-b"} {
			if code, body := get(t, r, host, "/"); code != 200 || !strings.HasPrefix(body, want+" ") {
				t.Errorf("%s: got %d %q, want %s", host, code, body, want)
			}
		}
	})

	t.Run("unknown host does not reach an app", func(t *testing.T) {
		code, body := get(t, r, "unknown.example.test", "/")
		if code != http.StatusNotFound || strings.Contains(body, "app-") {
			t.Errorf("got %d %q", code, body)
		}
	})

	t.Run("application Authorization passes through unchanged", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, r.vhost+"/", nil)
		req.Host = "a.example.test"
		req.Header.Set("Authorization", "Bearer app-own-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), `auth="Bearer app-own-token"`) {
			t.Errorf("got %q", body)
		}
	})

	t.Run("large POST body streams intact", func(t *testing.T) {
		payload := make([]byte, 16<<20)
		_, _ = rand.Read(payload)
		req, _ := http.NewRequest(http.MethodPost, r.vhost+"/", bytes.NewReader(payload))
		req.Host = "b.example.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := fmt.Sprintf("app-b %d %x", len(payload), sha256.Sum256(payload))
		if string(body) != want {
			t.Errorf("got %q, want %q", body, want)
		}
	})

	t.Run("large download streams intact", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, r.vhost+"/big", nil)
		req.Host = "a.example.test"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		n, err := io.Copy(io.Discard, resp.Body)
		if err != nil || n != 32<<20 {
			t.Errorf("got %d bytes, err %v", n, err)
		}
	})
}

func TestWrongTokenFails(t *testing.T) {
	bin := binDir(t)
	r := startRelay(t, bin)
	cfg := writeFrpc(t, r, "wrong-token", trusted(r), proxy{"a", "a.example.test", fixture(t, "app-a")})
	expectLoginFailure(t, bin, cfg, "token in login doesn't match")
}

func TestUntrustedCAFails(t *testing.T) {
	bin := binDir(t)
	r := startRelay(t, bin)
	// The system bundle does not contain the test CA.
	bundle := "/etc/ssl/cert.pem" // macOS, Alpine
	if _, err := os.Stat(bundle); err != nil {
		bundle = "/etc/ssl/certs/ca-certificates.crt" // Debian, Ubuntu
	}
	cfg := writeFrpc(t, r, token, fmt.Sprintf("transport.tls.trustedCaFile = %q\ntransport.tls.serverName = \"example.com\"", bundle),
		proxy{"a", "a.example.test", fixture(t, "app-a")})
	expectLoginFailure(t, bin, cfg, "certificate")
}

func TestWrongServerNameFails(t *testing.T) {
	bin := binDir(t)
	r := startRelay(t, bin)
	cfg := writeFrpc(t, r, token, fmt.Sprintf("transport.tls.trustedCaFile = %q\ntransport.tls.serverName = \"wrong.example.org\"", r.caFile),
		proxy{"a", "a.example.test", fixture(t, "app-a")})
	expectLoginFailure(t, bin, cfg, "certificate")
}

// TestNoCAFileSkipsVerification documents an upstream hazard in frp: with
// transport.protocol = "wss" and no transport.tls.trustedCaFile, frpc sets
// InsecureSkipVerify (pkg/transport/tls.go, NewClientTLSConfig). Generated
// configs must therefore always set trustedCaFile. If this test starts
// failing, upstream has begun verifying by default; revisit the generator.
func TestNoCAFileSkipsVerification(t *testing.T) {
	bin := binDir(t)
	r := startRelay(t, bin)
	cfg := writeFrpc(t, r, token, "", proxy{"a", "a.example.test", fixture(t, "app-a")})
	start(t, filepath.Join(bin, "frpc"), nil, "-c", cfg)
	waitRoute(t, r, "a.example.test")
}
