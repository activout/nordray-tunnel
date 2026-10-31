package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// relayServerName is the fixed name agents verify on the anycast transport.
// The Anycast IP is not in the certificate, so the address can change
// without reissuing it.
const relayServerName = "relay.nordray.internal"

// newRelayPKI creates an installation CA and signs one relay server
// certificate with it. The CA key is discarded: nobody, including the
// operator, can issue another certificate that agents of this installation
// would trust.
func newRelayPKI(installation string) (caPEM, certPEM, keyPEM string, err error) {
	serial := func() *big.Int {
		n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
		return n
	}
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	ca := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Nordray Tunnel relay CA (" + installation + ")"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return
	}
	ca, _ = x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	leaf := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: relayServerName},
		DNSNames:     []string{relayServerName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	enc := func(t string, b []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: t, Bytes: b})) }
	return enc("CERTIFICATE", caDER), enc("CERTIFICATE", der), enc("PRIVATE KEY", keyDER), nil
}
