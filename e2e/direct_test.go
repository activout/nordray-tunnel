package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// relayName is the fixed server name that generated frpc configs verify for
// direct (Anycast) agents; the Anycast IP itself is not in the certificate.
const relayName = "relay.nordray.internal"

type pki struct{ caFile, certFile, keyFile string }

// newPKI creates an installation CA and a server certificate for relayName,
// the way setup is meant to.
func newPKI(t *testing.T) pki {
	dir := t.TempDir()
	write := func(name, typ string, der []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Nordray Tunnels test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: relayName}, DNSNames: []string{relayName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	return pki{
		caFile:   write("ca.pem", "CERTIFICATE", caDER),
		certFile: write("tls.crt", "CERTIFICATE", der),
		keyFile:  write("tls.key", "PRIVATE KEY", keyDER),
	}
}

// For direct TCP the TLS handshake runs lazily under the mux session, so a
// verification failure surfaces as "session shutdown" rather than an x509
// error. TestDirectTLSRoundTrip differs only in the CA/server name, which
// isolates the cause.
const directTLSFailure = "session shutdown"

func directTLS(caFile, serverName string) string {
	return fmt.Sprintf("transport.tls.enable = true\ntransport.tls.trustedCaFile = %q\ntransport.tls.serverName = %q", caFile, serverName)
}

func startDirectRelay(t *testing.T, bin string, p pki, force bool) relay {
	return startRelay(t, bin, "NORDRAY_TLS_CERT_FILE="+p.certFile, "NORDRAY_TLS_KEY_FILE="+p.keyFile,
		fmt.Sprintf("NORDRAY_TLS_FORCE=%t", force))
}

func TestDirectTLSRoundTrip(t *testing.T) {
	bin := binDir(t)
	p := newPKI(t)
	r := startDirectRelay(t, bin, p, true)
	cfg := writeFrpcTo(t, r.direct, "tcp", token, directTLS(p.caFile, relayName), proxy{"a", "a.example.test", fixture(t, "app-a")})
	start(t, filepath.Join(bin, "frpc"), nil, "-c", cfg)
	waitRoute(t, r, "a.example.test")
}

func TestDirectTLSUntrustedCAFails(t *testing.T) {
	bin := binDir(t)
	r := startDirectRelay(t, bin, newPKI(t), true)
	other := newPKI(t) // a different installation's CA
	cfg := writeFrpcTo(t, r.direct, "tcp", token, directTLS(other.caFile, relayName), proxy{"a", "a.example.test", fixture(t, "app-a")})
	expectLoginFailure(t, bin, cfg, directTLSFailure)
}

func TestDirectTLSWrongServerNameFails(t *testing.T) {
	bin := binDir(t)
	p := newPKI(t)
	r := startDirectRelay(t, bin, p, true)
	cfg := writeFrpcTo(t, r.direct, "tcp", token, directTLS(p.caFile, "wrong.example.org"), proxy{"a", "a.example.test", fixture(t, "app-a")})
	expectLoginFailure(t, bin, cfg, directTLSFailure)
}

func TestForceRejectsPlaintextAgent(t *testing.T) {
	bin := binDir(t)
	r := startDirectRelay(t, bin, newPKI(t), true)
	cfg := writeFrpcTo(t, r.direct, "tcp", token, "transport.tls.enable = false", proxy{"a", "a.example.test", fixture(t, "app-a")})
	out := expectLoginFailureOutput(t, bin, cfg)
	t.Logf("plaintext agent rejected: %s", lastLine(out))
}

// TestForceBlocksWSS documents why "both" mode cannot force TLS: WSS agents
// reach frps as plain WebSocket once the CDN has terminated TLS.
func TestForceBlocksWSS(t *testing.T) {
	bin := binDir(t)
	r := startDirectRelay(t, bin, newPKI(t), true)
	cfg := writeFrpc(t, r, token, trusted(r), proxy{"a", "a.example.test", fixture(t, "app-a")})
	expectLoginFailureOutput(t, bin, cfg)
}

func TestBothModeServesWSSAndDirect(t *testing.T) {
	bin := binDir(t)
	p := newPKI(t)
	r := startDirectRelay(t, bin, p, false)
	wss := writeFrpc(t, r, token, trusted(r), proxy{"a", "a.example.test", fixture(t, "app-a")})
	direct := writeFrpcTo(t, r.direct, "tcp", token, directTLS(p.caFile, relayName), proxy{"b", "b.example.test", fixture(t, "app-b")})
	start(t, filepath.Join(bin, "frpc"), nil, "-c", wss)
	start(t, filepath.Join(bin, "frpc"), nil, "-c", direct)
	waitRoute(t, r, "a.example.test")
	waitRoute(t, r, "b.example.test")
}
