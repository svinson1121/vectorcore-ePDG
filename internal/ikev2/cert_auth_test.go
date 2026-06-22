package ikev2

// Tests for the TS 33.402 §8.2.1/8.2.2 fix: the ePDG must load its private
// key and sign the responder AUTH payload in the first IKE_AUTH response.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vectorcore-epdg/internal/config"

	"github.com/free5gc/ike/message"
)

const (
	repoCertFile = "../../config/certs/epdgCert.pem"
	repoKeyFile  = "../../config/certs/epdgKey.pem"
	repoEPDGName = "epdg2.epc.mnc435.mcc311.3gppnetwork.org"
)

func newTestServerForCert(t *testing.T) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(&Config{ListenAddr: "127.0.0.1"}, log)
}

func TestSetFullConfigLoadsCertAndKey(t *testing.T) {
	srv := newTestServerForCert(t)
	cfg := &config.Config{}
	cfg.EPDG.Name = repoEPDGName
	cfg.IKEv2.CertFile = repoCertFile
	cfg.IKEv2.KeyFile = repoKeyFile

	if err := srv.SetFullConfig(cfg); err != nil {
		t.Fatalf("SetFullConfig() error = %v", err)
	}
	if srv.privateKey == nil {
		t.Fatal("SetFullConfig() did not populate privateKey")
	}
	if len(srv.certDER) == 0 {
		t.Fatal("SetFullConfig() did not populate certDER")
	}

	cert, err := x509.ParseCertificate(srv.certDER)
	if err != nil {
		t.Fatalf("re-parse loaded certDER: %v", err)
	}
	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("certificate public key type = %T, want *rsa.PublicKey", cert.PublicKey)
	}
	if certPub.N.Cmp(srv.privateKey.N) != 0 {
		t.Fatal("loaded private key does not match certificate public key")
	}
}

func TestSetFullConfigRequiresKeyFile(t *testing.T) {
	srv := newTestServerForCert(t)
	cfg := &config.Config{}
	cfg.EPDG.Name = repoEPDGName
	cfg.IKEv2.CertFile = repoCertFile
	// KeyFile intentionally left empty.

	if err := srv.SetFullConfig(cfg); err == nil {
		t.Fatal("SetFullConfig() with no key_file: want error, got nil")
	}
}

func TestSetFullConfigRequiresEPDGName(t *testing.T) {
	srv := newTestServerForCert(t)
	cfg := &config.Config{}
	cfg.IKEv2.CertFile = repoCertFile
	cfg.IKEv2.KeyFile = repoKeyFile
	// EPDG.Name intentionally left empty.

	if err := srv.SetFullConfig(cfg); err == nil {
		t.Fatal("SetFullConfig() with no epdg.name: want error, got nil")
	}
}

func TestSetFullConfigRejectsSANMismatch(t *testing.T) {
	srv := newTestServerForCert(t)
	cfg := &config.Config{}
	cfg.EPDG.Name = "not-the-epdg-name.example.org"
	cfg.IKEv2.CertFile = repoCertFile
	cfg.IKEv2.KeyFile = repoKeyFile

	err := srv.SetFullConfig(cfg)
	if err == nil {
		t.Fatal("SetFullConfig() with mismatched epdg.name: want error, got nil")
	}
}

func TestSetFullConfigRejectsKeyCertMismatch(t *testing.T) {
	dir := t.TempDir()
	// Cert/key pair #1.
	cert1PEM, _ := generateSelfSignedRSACert(t, repoEPDGName)
	// Cert/key pair #2 — unrelated key, used as the "wrong" private key.
	_, key2PEM := generateSelfSignedRSACert(t, repoEPDGName)

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, cert1PEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, key2PEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	srv := newTestServerForCert(t)
	cfg := &config.Config{}
	cfg.EPDG.Name = repoEPDGName
	cfg.IKEv2.CertFile = certPath
	cfg.IKEv2.KeyFile = keyPath

	if err := srv.SetFullConfig(cfg); err == nil {
		t.Fatal("SetFullConfig() with mismatched key/cert: want error, got nil")
	}
}

// TestSendEAPResponseIncludesSignatureAUTH is an end-to-end check of the fix:
// the first IKE_AUTH response (includeID=true) must carry an AUTH payload
// that verifies against the ePDG certificate's public key, computed over the
// RFC 7296 §2.15 ResponderSignedOctets construction.
func TestSendEAPResponseIncludesSignatureAUTH(t *testing.T) {
	srv := newTestServerForCert(t)
	cfg := &config.Config{}
	cfg.EPDG.Name = repoEPDGName
	cfg.IKEv2.CertFile = repoCertFile
	cfg.IKEv2.KeyFile = repoKeyFile
	if err := srv.SetFullConfig(cfg); err != nil {
		t.Fatalf("SetFullConfig() error = %v", err)
	}

	// Loopback UDP pair standing in for the UE.
	srvConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer srvConn.Close()
	ueConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ueConn.Close()
	ueAddr := ueConn.LocalAddr().(*net.UDPAddr)

	key := randomKey(t, encrAesCbc256.KeyLen())
	integKey := randomKey(t, integSha256_128.KeyLen())
	saKey := &ikeSAKey{
		encr: encrAesCbc256, integ: integSha256_128,
		prf:   prfSha256,
		SK_er: key, SK_ei: key, SK_ar: integKey, SK_ai: integKey,
		SK_pr: randomKey(t, 32), SK_pi: randomKey(t, 32),
	}
	sa := &ikeSA{
		saKey:       saKey,
		initRespRaw: []byte("fake-IKE_SA_INIT-response-bytes"),
		nonceI:      []byte("fake-nonce-initiator-fake-nonce-initiator"),
	}

	eapPayload := []byte{1, 1, 0, 4} // minimal EAP-Request header, body irrelevant here.
	srv.sendEAPResponse(srvConn, ueAddr, sa, 1, eapPayload, true, false)

	buf := make([]byte, 4096)
	_ = ueConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := ueConn.Read(buf)
	if err != nil {
		t.Fatalf("UE did not receive a response: %v", err)
	}

	innerType, plain, err := decryptSK(saKey, buf[:n])
	if err != nil {
		t.Fatalf("decryptSK() error = %v", err)
	}
	payloads, err := parseAuthPayloads(innerType, plain)
	if err != nil {
		t.Fatalf("parseAuthPayloads() error = %v", err)
	}

	if payloads.idr == nil {
		t.Fatal("response missing IDr payload")
	}
	if payloads.auth == nil {
		t.Fatal("response missing AUTH payload — ePDG is not signature-authenticated (TS 33.402 §8.2.1)")
	}
	if payloads.auth.AuthenticationMethod != message.RSADigitalSignature {
		t.Fatalf("AUTH method = %d, want %d (RSADigitalSignature)", payloads.auth.AuthenticationMethod, message.RSADigitalSignature)
	}

	// Recompute the expected ResponderSignedOctets and verify the signature
	// against the certificate's public key, exactly as a conformant UE would.
	idrBytes := buildIDAuthBytes(message.ID_FQDN, []byte(repoEPDGName))
	macedIDR := prfMAC(saKey.prf, saKey.SK_pr, idrBytes)
	responderSigned := concat(sa.initRespRaw, sa.nonceI, macedIDR)
	digest := sha1.Sum(responderSigned)

	cert, err := x509.ParseCertificate(srv.certDER)
	if err != nil {
		t.Fatalf("parse certDER: %v", err)
	}
	pub := cert.PublicKey.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest[:], payloads.auth.AuthenticationData); err != nil {
		t.Fatalf("signature does not verify against ePDG certificate: %v", err)
	}
}

// generateSelfSignedRSACert returns PEM-encoded cert and key for a throwaway
// self-signed certificate with the given dNSName SAN, used for negative tests.
func generateSelfSignedRSACert(t *testing.T, dnsName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
