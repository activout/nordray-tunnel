package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/zalando/go-keyring"
)

// fakeBunny models just enough of the Bunny API, as observed live on
// 31 October 2026, to exercise reconciliation.
type fakeBunny struct {
	mu        sync.Mutex
	calls     map[string]int // "METHOD /path" with numeric IDs kept
	fail      map[string]int // remaining injected failures per call key
	app       *fakeApp
	zones     map[int64]map[string]any
	hostnames map[int64][]string
	nextZone  int64
	shield    map[int64]map[string]any // by shield zone ID
	records   map[int64]map[string]any // DNS records in zone 9 (example.se)
	env       []mcEnv
	forceSSL  []string
}

type fakeApp struct {
	endpoints []map[string]any
}

func newFakeBunny(t *testing.T) *fakeBunny {
	f := &fakeBunny{calls: map[string]int{}, fail: map[string]int{}, zones: map[int64]map[string]any{},
		hostnames: map[int64][]string{}, nextZone: 100, shield: map[int64]map[string]any{}, records: map[int64]map[string]any{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	bunnyBaseURL = srv.URL
	return f
}

func (f *fakeBunny) addEndpoint(spec map[string]any) string {
	name := spec["displayName"].(string)
	id := "APP1-" + name
	e := map[string]any{"id": id, "displayName": name}
	if spec["anycast"] != nil {
		e["type"], e["publicHost"] = "anycast", "203.0.113.7:7000"
	} else {
		f.nextZone++
		z := f.nextZone
		f.zones[z] = map[string]any{"Id": z, "Name": fmt.Sprintf("mc-zone%d", z), "EnableWebSockets": true, "AddHostHeader": false}
		e["type"], e["pullZoneId"], e["publicHost"] = "cdn", fmt.Sprint(z), fmt.Sprintf("mc-zone%d.bunny.run", z)
	}
	f.app.endpoints = append(f.app.endpoints, e)
	return id
}

func (f *fakeBunny) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("AccessKey") != "test-key" {
		http.Error(w, `{"Message":"unauthorised"}`, http.StatusUnauthorized)
		return
	}
	key := r.Method + " " + r.URL.Path
	f.calls[key]++
	if f.fail[key] > 0 {
		f.fail[key]--
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"Message":"injected failure"}`)
		return
	}
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	notFound := func() { w.WriteHeader(http.StatusNotFound); _, _ = io.WriteString(w, `{"Message":"not found"}`) }
	var id int64
	p := r.URL.Path
	switch {
	case key == "GET /mc/registries":
		reply(map[string]any{"items": []map[string]any{{"id": 1156, "hostName": "ghcr.io", "isPublic": true}, {"id": 5370, "hostName": "ghcr.io", "isPublic": false}}})
	case key == "POST /mc/registries/digest":
		reply(map[string]any{"digest": "sha256:" + strings.Repeat("ab", 32)})
	case key == "POST /mc/apps":
		f.app = &fakeApp{}
		tmpl := body["containerTemplates"].([]any)[0].(map[string]any)
		for _, e := range tmpl["endpoints"].([]any) {
			f.addEndpoint(e.(map[string]any))
		}
		f.env = decodeEnv(tmpl["environmentVariables"])
		reply(map[string]any{"id": "APP1"})
	case key == "GET /mc/apps/APP1":
		if f.app == nil {
			notFound()
			return
		}
		reply(map[string]any{"id": "APP1", "status": "active", "containerTemplates": []any{map[string]any{
			"id": "C1", "imageTag": "sha-test", "imageDigest": "sha256:" + strings.Repeat("ab", 32), "environmentVariables": f.env, "endpoints": f.app.endpoints}}})
	case key == "GET /mc/apps/APP1/endpoints":
		reply(map[string]any{"items": f.app.endpoints})
	case key == "PATCH /mc/apps/APP1/containers/C1":
		f.env = decodeEnv(body["environmentVariables"])
	case key == "POST /mc/apps/APP1/containers/C1/endpoints":
		reply(map[string]any{"id": f.addEndpoint(body)})
	case strings.HasPrefix(key, "DELETE /mc/apps/APP1/endpoints/"):
		kept := f.app.endpoints[:0]
		for _, e := range f.app.endpoints {
			if e["id"] != strings.TrimPrefix(p, "/mc/apps/APP1/endpoints/") {
				kept = append(kept, e)
			}
		}
		f.app.endpoints = kept
	case key == "DELETE /mc/apps/APP1":
		f.app = nil
	case scan(p, "/pullzone/%d/addHostname", &id):
		f.hostnames[id] = append(f.hostnames[id], body["Hostname"].(string))
	case scan(p, "/pullzone/%d/removeHostname", &id):
		kept := []string{}
		for _, h := range f.hostnames[id] {
			if h != body["Hostname"] {
				kept = append(kept, h)
			}
		}
		f.hostnames[id] = kept
	case p == "/pullzone/loadFreeCertificate":
	case scan(p, "/pullzone/%d/setForceSSL", &id):
		f.forceSSL = append(f.forceSSL, body["Hostname"].(string))
	case scan(p, "/pullzone/%d", &id):
		z, ok := f.zones[id]
		if !ok {
			notFound()
			return
		}
		switch r.Method {
		case http.MethodGet:
			hs := []map[string]any{}
			for _, h := range f.hostnames[id] {
				hs = append(hs, map[string]any{"Value": h, "HasCertificate": false})
			}
			z["Hostnames"] = hs
			reply(z)
		case http.MethodPost:
			for k, v := range body {
				z[k] = v
			}
		case http.MethodDelete:
			delete(f.zones, id)
		}
	case scan(p, "/shield/shield-zone/get-by-pullzone/%d", &id):
		for sid, z := range f.shield {
			if z["pullZoneId"] == float64(id) {
				reply(map[string]any{"data": map[string]any{"shieldZoneId": sid}})
				return
			}
		}
		notFound()
	case key == "POST /shield/shield-zone":
		sid := int64(500 + len(f.shield))
		f.shield[sid] = map[string]any{"pullZoneId": body["pullZoneId"], "learningMode": true}
		reply(map[string]any{"data": map[string]any{"shieldZone": map[string]any{"shieldZoneId": sid}}})
	case key == "PATCH /shield/shield-zone":
		sid := int64(body["shieldZoneId"].(float64))
		for k, v := range body["shieldZone"].(map[string]any) {
			f.shield[sid][k] = v
		}
	case p == "/dnszone":
		reply(map[string]any{"Items": []map[string]any{{"Id": 9, "Domain": "example.se"}, {"Id": 8, "Domain": "se"}}, "HasMoreItems": false})
	case key == "GET /dnszone/9":
		recs := []map[string]any{}
		for rid, rec := range f.records {
			recs = append(recs, map[string]any{"Id": rid, "Type": rec["Type"], "Name": rec["Name"], "Value": rec["Value"]})
		}
		reply(map[string]any{"Id": 9, "Domain": "example.se", "Records": recs})
	case key == "PUT /dnszone/9/records":
		rid := int64(700 + len(f.records))
		f.records[rid] = body
		reply(map[string]any{"Id": rid})
	case scan(p, "/dnszone/9/records/%d", &id):
		delete(f.records, id)
	default:
		w.WriteHeader(http.StatusTeapot)
		_, _ = fmt.Fprintf(w, `{"Message":"fake has no %s"}`, key)
	}
}

// scan matches path exactly against a format with one %d.
func scan(path, format string, id *int64) bool {
	n, _ := fmt.Sscanf(path, format, id)
	return n == 1 && fmt.Sprintf(format, *id) == path
}

func decodeEnv(v any) []mcEnv {
	var env []mcEnv
	b, _ := json.Marshal(v)
	_ = json.Unmarshal(b, &env)
	return env
}

func envValue(env []mcEnv, name string) string {
	for _, e := range env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}

func setupTest(t *testing.T) *fakeBunny {
	keyring.MockInit()
	root := t.TempDir()
	configRoot = func() (string, error) { return root, nil }
	pollInterval = 0
	waitForEdge = func(string) {}
	waitClosed = func(string) {}
	return newFakeBunny(t)
}

func newTestState(t *testing.T, transport string) *State {
	img, err := parseImage("ghcr.io/activout/nordray-tunnel-relay:sha-test")
	if err != nil {
		t.Fatal(err)
	}
	return &State{Name: "home", Region: "DK", Transport: transport, Image: img}
}

func client() *bunny { return newBunny("test-key") }

func TestSetupIsIdempotent(t *testing.T) {
	f := setupTest(t)
	s := newTestState(t, "wss")
	if err := reconcile(context.Background(), client(), s, true); err != nil {
		t.Fatal(err)
	}
	again, _ := loadState("home")
	if err := reconcile(context.Background(), client(), again, true); err != nil {
		t.Fatal(err)
	}
	if n := f.calls["POST /mc/apps"]; n != 1 {
		t.Errorf("created the app %d times", n)
	}
	if n := f.calls["POST /shield/shield-zone"]; n != 1 {
		t.Errorf("created Shield %d times", n)
	}
	if n := f.calls["PATCH /mc/apps/APP1/containers/C1"]; n != 0 {
		t.Errorf("an unchanged rerun patched the container %d times, restarting the relay", n)
	}
	if again.Image.RegistryID != "5370" {
		t.Errorf("registry %q; want the private registry for the host", again.Image.RegistryID)
	}
	if !strings.HasPrefix(again.Image.Digest, "sha256:") || again.TunnelHost == "" || again.AppPullZoneID == 0 {
		t.Errorf("state not filled in: %+v", again)
	}
	z := f.zones[again.AppPullZoneID]
	if z["AddHostHeader"] != true || z["EnableWebSockets"] != false || z["EnableSmartCache"] != false {
		t.Errorf("app zone settings: %v", z)
	}
	sz := f.shield[again.ShieldZoneID]
	if sz["learningMode"] != false || sz["wafExecutionMode"] != float64(1) {
		t.Errorf("Shield not enforcing: %v", sz)
	}
	if len(envValue(f.env, "NORDRAY_TUNNEL_TOKEN")) < 32 || envValue(f.env, "NORDRAY_TLS_FORCE") != "false" {
		t.Errorf("relay env: token length %d, force %q", len(envValue(f.env, "NORDRAY_TUNNEL_TOKEN")), envValue(f.env, "NORDRAY_TLS_FORCE"))
	}
	b, _ := os.ReadFile(filepath.Join(must(stateDir("home")), "state.json"))
	if strings.Contains(string(b), envValue(f.env, "NORDRAY_TUNNEL_TOKEN")) {
		t.Error("state.json contains the tunnel token")
	}
}

func TestSetupResumesAfterPartialFailure(t *testing.T) {
	f := setupTest(t)
	f.fail["POST /shield/shield-zone"] = 1
	s := newTestState(t, "wss")
	if err := reconcile(context.Background(), client(), s, true); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("want the injected failure, got %v", err)
	}
	saved, _ := loadState("home")
	if saved.AppID != "APP1" || saved.AppPullZoneID == 0 {
		t.Fatalf("progress not saved: %+v", saved)
	}
	if err := reconcile(context.Background(), client(), saved, true); err != nil {
		t.Fatal(err)
	}
	if f.calls["POST /mc/apps"] != 1 || len(f.shield) != 1 {
		t.Errorf("apps created %d, Shield zones %d", f.calls["POST /mc/apps"], len(f.shield))
	}
}

func TestSwitchToAnycast(t *testing.T) {
	f := setupTest(t)
	s := newTestState(t, "wss")
	if err := reconcile(context.Background(), client(), s, true); err != nil {
		t.Fatal(err)
	}
	tunnelZone := s.TunnelPullZoneID
	s.Transport = "anycast"
	if err := reconcile(context.Background(), client(), s, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.zones[tunnelZone]; ok {
		t.Error("tunnel pull zone not deleted")
	}
	if s.TunnelEndpointID != "" || s.AnycastAddr != "203.0.113.7:7000" {
		t.Errorf("endpoints: tunnel %q anycast %q", s.TunnelEndpointID, s.AnycastAddr)
	}
	key := envValue(f.env, "NORDRAY_TLS_KEY")
	if envValue(f.env, "NORDRAY_TLS_FORCE") != "true" || !strings.Contains(key, "PRIVATE KEY") || s.CACert == "" {
		t.Error("relay TLS not configured")
	}
	b, _ := os.ReadFile(filepath.Join(must(stateDir("home")), "state.json"))
	if strings.Contains(string(b), "PRIVATE KEY") {
		t.Error("state.json contains the relay private key")
	}
	cfg, err := buildFrpcConfig(s, "tok", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerAddr != "203.0.113.7" || cfg.ServerPort != 7000 || cfg.Transport.Protocol != "tcp" ||
		!cfg.Transport.TLS.Enable || cfg.Transport.TLS.ServerName != relayServerName {
		t.Errorf("anycast frpc config: %+v", cfg)
	}
}

func TestAddAndRemoveHostname(t *testing.T) {
	f := setupTest(t)
	s := newTestState(t, "wss")
	if err := reconcile(context.Background(), client(), s, true); err != nil {
		t.Fatal(err)
	}
	s.Proxies = []Proxy{{Name: "web", Hostname: "app.example.se", LocalIP: "127.0.0.1", LocalPort: 8080}}
	if err := publish(context.Background(), client(), s, &s.Proxies[0]); err != nil {
		t.Fatal(err)
	}
	p := s.Proxies[0]
	rec := f.records[p.DNSRecordID]
	if p.DNSZoneID != 9 || rec["Type"] != float64(7) || rec["Name"] != "app" || rec["PullZoneId"] != float64(s.AppPullZoneID) {
		t.Errorf("DNS record %d: %v", p.DNSRecordID, rec)
	}
	if got := f.hostnames[s.AppPullZoneID]; len(got) != 1 || got[0] != "app.example.se" {
		t.Errorf("hostnames %v", got)
	}
	if len(f.forceSSL) != 1 || f.forceSSL[0] != "app.example.se" {
		t.Errorf("force SSL %v", f.forceSSL)
	}
	// Publishing again neither duplicates the hostname nor the record.
	if err := publish(context.Background(), client(), s, &s.Proxies[0]); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 1 || len(f.hostnames[s.AppPullZoneID]) != 1 {
		t.Errorf("duplicated: %d records, hostnames %v", len(f.records), f.hostnames[s.AppPullZoneID])
	}
	if err := destroy(context.Background(), client(), s); err != nil {
		t.Fatal(err)
	}
	if len(f.records) != 0 || len(f.zones) != 0 || f.app != nil {
		t.Errorf("left behind: %d records, %d zones, app %v", len(f.records), len(f.zones), f.app != nil)
	}
	if _, err := os.Stat(must(stateDir("home"))); !os.IsNotExist(err) {
		t.Error("state directory not removed")
	}
}

func TestAddRefusesForeignDNSRecord(t *testing.T) {
	f := setupTest(t)
	s := newTestState(t, "wss")
	if err := reconcile(context.Background(), client(), s, true); err != nil {
		t.Fatal(err)
	}
	f.records[42] = map[string]any{"Type": float64(0), "Name": "app", "Value": "192.0.2.1"}
	s.Proxies = []Proxy{{Name: "web", Hostname: "app.example.se", LocalIP: "127.0.0.1", LocalPort: 8080}}
	err := publish(context.Background(), client(), s, &s.Proxies[0])
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("want refusal, got %v", err)
	}
	if f.records[42]["Value"] != "192.0.2.1" || len(f.records) != 1 {
		t.Error("foreign record touched")
	}
}

func TestAgentFiles(t *testing.T) {
	setupTest(t)
	s := &State{Name: "home", Transport: "wss", TunnelHost: "mc-x.bunny.run",
		Proxies: []Proxy{{Name: "web", Hostname: "app.example.se", LocalIP: "127.0.0.1", LocalPort: 8080}}}
	cfg, err := buildFrpcConfig(s, "secret-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path, err := writeAgentFiles(filepath.Join(dir, "agent"), s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if _, err := toml.DecodeFile(path, &back); err != nil {
		t.Fatal(err)
	}
	tr := back["transport"].(map[string]any)
	px := back["proxies"].([]map[string]any)[0]
	if px["requestHeaders"].(map[string]any)["set"].(map[string]any)["X-Forwarded-Proto"] != "https" {
		t.Errorf("proxy headers: %v", px)
	}
	if back["serverPort"] != int64(443) || tr["protocol"] != "wss" || tr["tls"].(map[string]any)["trustedCaFile"] != caFileName {
		t.Errorf("frpc.toml: %v", back)
	}
	for _, f := range []string{path, filepath.Join(dir, "agent", caFileName)} {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
	}
	ca, _ := os.ReadFile(filepath.Join(dir, "agent", caFileName))
	if blk, _ := pem.Decode(ca); blk == nil || strings.Count(string(ca), "BEGIN CERTIFICATE") < 50 {
		t.Error("CA bundle is not a usable PEM root set")
	}
}

func TestRunForwardsExitCode(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "frpc")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\n[ -f ca.pem ] || exit 9\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "ca.pem"), nil, 0o600)
	err := runChild(fake, filepath.Join(dir, "frpc.toml"))
	if e, ok := err.(exitError); !ok || e.code != 3 {
		t.Fatalf("want exit 3 (frpc started in the config directory), got %v", err)
	}
}

func TestParseImageAndLocal(t *testing.T) {
	img, err := parseImage("ghcr.io/activout/nordray-tunnel-relay:sha-abc")
	if err != nil || img.Namespace != "activout" || img.Name != "nordray-tunnel-relay" || img.Tag != "sha-abc" {
		t.Errorf("%+v %v", img, err)
	}
	for _, bad := range []string{"relay:1", "ghcr.io/relay:1", "ghcr.io/a/relay", "ghcr.io/a/relay:latest", "ghcr.io/a/relay@sha256:00"} {
		if _, err := parseImage(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if sc, ip, port, err := parseLocal("http://127.0.0.1:8080"); err != nil || sc != "http" || ip != "127.0.0.1" || port != 8080 {
		t.Errorf("%s %s %d %v", sc, ip, port, err)
	}
	if sc, ip, port, err := parseLocal("https://nas.lan"); err != nil || sc != "https" || ip != "nas.lan" || port != 443 {
		t.Errorf("%s %s %d %v", sc, ip, port, err)
	}
	for _, bad := range []string{"ftp://host", "127.0.0.1:8080", "http://u:p@host", "http://host/path"} {
		if _, _, _, err := parseLocal(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	s := &State{Name: "x", Transport: "wss", TunnelHost: "t", Proxies: []Proxy{{Name: "nas", Hostname: "nas.example.se", LocalScheme: "https", LocalIP: "nas.lan", LocalPort: 8443}}}
	cfg, err := buildFrpcConfig(s, "tok", nil)
	if err != nil || cfg.Proxies[0].Plugin == nil || cfg.Proxies[0].Plugin.Type != "http2https" || cfg.Proxies[0].Plugin.LocalAddr != "nas.lan:8443" {
		t.Errorf("https proxy: %+v %v", cfg.Proxies[0], err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestInstallFrpcVerifiesChecksum(t *testing.T) {
	// A fake release with a tar.gz holding frpc; the checksum does not match
	// the pinned one, so the install must refuse it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "not the real archive")
	}))
	defer srv.Close()
	githubBaseURL = srv.URL
	dir := t.TempDir()
	binDir = func(v string) (string, error) { return filepath.Join(dir, v), nil }
	_, err := installFrpc(frpVersion)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("want checksum mismatch, got %v", err)
	}
	if installedFrpc(frpVersion) != "" {
		t.Error("frpc installed despite the mismatch")
	}
}

func TestFileSecretStore(t *testing.T) {
	setupTest(t)
	t.Setenv("NORDRAY_TUNNEL_SECRET_STORE", "file")
	tok, err := ensureSecret("home", "tunnel-token")
	if err != nil || len(tok) != 64 {
		t.Fatalf("%q %v", tok, err)
	}
	if again, _ := ensureSecret("home", "tunnel-token"); again != tok {
		t.Error("token not persisted")
	}
	path, _, _ := secretsFile()
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("secrets.json: %v %v", fi, err)
	}
	deleteSecret("home", "tunnel-token")
	if v, _ := getSecret("home", "tunnel-token"); v != "" {
		t.Error("not deleted")
	}
}

func TestFindFrpcMakesRelativePathAbsolute(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "frpc"), []byte("#!/bin/sh\necho 0.71.1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	bin, err := findFrpc("./frpc")
	if err != nil || !filepath.IsAbs(bin) {
		t.Fatalf("%q %v", bin, err)
	}
}
