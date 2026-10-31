package e2e

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHTTPSLocalTarget runs an HTTPS local service behind frp's http2https
// plugin, the way add --local https://... configures it. The plugin does not
// verify the service's certificate (frp limitation, issue #9), which this
// test also pins: the service uses a certificate no one trusts.
func TestHTTPSLocalTarget(t *testing.T) {
	bin := binDir(t)
	r := startRelay(t, bin)
	svc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintf(w, "tls=%t host=%s proto=%s", req.TLS != nil, req.Host, req.Header.Get("X-Forwarded-Proto"))
	}))
	t.Cleanup(svc.Close)
	port := svc.Listener.Addr().(*net.TCPAddr).Port

	cfg := writeFrpc(t, r, token, trusted(r))
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, `[[proxies]]
name = "nas"
type = "http"
customDomains = ["nas.example.test"]
requestHeaders.set.X-Forwarded-Proto = "https"
[proxies.plugin]
type = "http2https"
localAddr = "127.0.0.1:%d"
`, port)
	f.Close()
	start(t, filepath.Join(bin, "frpc"), nil, "-c", cfg)
	waitRoute(t, r, "nas.example.test")

	code, body := get(t, r, "nas.example.test", "/")
	if code != http.StatusOK || !strings.Contains(body, "tls=true") || !strings.Contains(body, "host=nas.example.test") || !strings.Contains(body, "proto=https") {
		t.Errorf("HTTP %d %q", code, body)
	}
}
