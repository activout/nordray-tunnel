//go:build live

// Package live checks a running installation through the real Bunny CDN. It
// is run by the manual live-e2e workflow after nordray-tunnel setup, add and
// run; it creates nothing itself.
//
//	LIVE_HOSTNAME      public hostname published with add
//	LIVE_DEFAULT_HOST  the app pull zone's own hostname (mc-*.b-cdn.net)
package live

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

var client = &http.Client{
	Timeout:       2 * time.Minute,
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func env(t *testing.T, name string) string {
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set", name)
	}
	return v
}

type echo struct {
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// get fetches url and decodes the fixture's echo. A Shield block is reported
// as such, because runners in data centres can be challenged.
func get(t *testing.T, url string, headers map[string]string) (int, echo, []byte) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusForbidden {
		t.Logf("HTTP 403 from %s: Shield may be challenging this runner's IP", resp.Header.Get("Server"))
	}
	var e echo
	_ = json.Unmarshal(body, &e)
	return resp.StatusCode, e, body
}

func TestMain(m *testing.M) {
	// The certificate and the agent can take a little while to settle.
	host := os.Getenv("LIVE_HOSTNAME")
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		resp, err := client.Get("https://" + host + "/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(5 * time.Second)
	}
	os.Exit(m.Run())
}

func TestServiceSeesOriginalRequest(t *testing.T) {
	host := env(t, "LIVE_HOSTNAME")
	code, e, body := get(t, "https://"+host+"/api/check?x=1", map[string]string{
		"Authorization":     "Bearer app-own-token",
		"X-Custom":          "kept",
		"X-Forwarded-Proto": "gopher",
		"X-Forwarded-For":   "6.6.6.6",
	})
	if code != http.StatusOK {
		t.Fatalf("HTTP %d: %.200s", code, body)
	}
	h := e.Headers
	for k, want := range map[string]string{"Authorization": "Bearer app-own-token", "X-Custom": "kept", "Host": host, "X-Forwarded-Proto": "https"} {
		if h[k] != want {
			t.Errorf("%s = %q, want %q", k, h[k], want)
		}
	}
	if e.Path != "/api/check?x=1" {
		t.Errorf("path %q", e.Path)
	}
	if strings.HasPrefix(h["X-Forwarded-For"], "6.6.6.6") || h["X-Real-Ip"] == "6.6.6.6" {
		t.Errorf("spoofed client IP survived: X-Forwarded-For %q, X-Real-Ip %q", h["X-Forwarded-For"], h["X-Real-Ip"])
	}
	t.Logf("headers at the service: %v", h)
}

func TestPlainHTTPRedirects(t *testing.T) {
	host := env(t, "LIVE_HOSTNAME")
	resp, err := client.Get("http://" + host + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 3 || !strings.HasPrefix(resp.Header.Get("Location"), "https://"+host) {
		t.Errorf("HTTP %d Location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestLargeTransfers(t *testing.T) {
	host := env(t, "LIVE_HOSTNAME")
	resp, err := client.Get("https://" + host + "/big")
	if err != nil {
		t.Fatal(err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if err != nil || n != 32<<20 {
		t.Errorf("download: %d bytes, %v", n, err)
	}

	payload := make([]byte, 16<<20)
	_, _ = rand.Read(payload)
	resp, err = client.Post("https://"+host+"/upload", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Bytes  int64  `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&r)
	resp.Body.Close()
	sum := sha256.Sum256(payload)
	if r.Bytes != int64(len(payload)) || r.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("upload: got %d bytes %s", r.Bytes, r.SHA256)
	}
}

func TestDefaultHostnameDoesNotReachService(t *testing.T) {
	host := env(t, "LIVE_DEFAULT_HOST")
	code, e, body := get(t, "https://"+host+"/", nil)
	if code != http.StatusNotFound || e.Headers != nil {
		t.Errorf("https://%s/: HTTP %d %s", host, code, fmt.Sprintf("%.120s", body))
	}
	if !bytes.Contains(body, []byte("Nordray Tunnel")) {
		t.Errorf("https://%s/ does not show the Nordray Tunnel error page", host)
	}
}
