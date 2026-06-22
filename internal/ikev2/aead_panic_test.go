package ikev2

// Regression tests for the AES-GCM nil-integrity-algorithm panic: when AEAD
// is negotiated, negotiatedProposal.integ (and ikeSAKey.integ) is nil by
// design (RFC 5282 §3 — combined-mode ciphers carry their own integrity
// check). sendEncryptedRaw and sendEncryptedRequest used to compute the IKE
// header's Length field by calling sa.saKey.integ.OutputLen() unconditionally,
// which dereferences a nil *integAlg and panics. Both now go through
// encryptedSKMessageLen, which branches on IsAEAD() exactly like encryptSK.

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/free5gc/ike/message"
)

func TestEncryptedSKMessageLenMatchesActualOutputCBC(t *testing.T) {
	key := randomKey(t, encrAesCbc256.KeyLen())
	integKey := randomKey(t, integSha256_128.KeyLen())
	saKey := &ikeSAKey{
		encr: encrAesCbc256, integ: integSha256_128,
		SK_er: key, SK_ei: key, SK_ar: integKey, SK_ai: integKey,
	}
	plain := []byte("arbitrary inner payload bytes for length check")

	got, err := encryptedSKMessageLen(saKey, len(plain))
	if err != nil {
		t.Fatalf("encryptedSKMessageLen() error = %v", err)
	}
	out, err := encryptSK(saKey, 1, plain, make([]byte, 28))
	if err != nil {
		t.Fatalf("encryptSK() error = %v", err)
	}
	if got != len(out) {
		t.Fatalf("encryptedSKMessageLen() = %d, want %d (actual encryptSK output length)", got, len(out))
	}
}

func TestEncryptedSKMessageLenMatchesActualOutputAEAD(t *testing.T) {
	for _, encr := range []*encrAlg{encrAesGcm16_128, encrAesGcm16_256} {
		key := randomKey(t, encr.KeyLen())
		saKey := &ikeSAKey{encr: encr, SK_er: key, SK_ei: key} // integ intentionally nil
		plain := []byte("arbitrary inner payload bytes for length check, AEAD")

		got, err := encryptedSKMessageLen(saKey, len(plain))
		if err != nil {
			t.Fatalf("encryptedSKMessageLen() error = %v", err)
		}
		header := make([]byte, 28)
		out, err := encryptSK(saKey, 1, plain, header)
		if err != nil {
			t.Fatalf("encryptSK() error = %v", err)
		}
		if got != len(out) {
			t.Fatalf("encryptedSKMessageLen() = %d, want %d (actual encryptSK output length)", got, len(out))
		}
	}
}

// TestSendEncryptedRawAEADNoPanic reproduces the exact crash: an IKE SA that
// negotiated AES-GCM (the server's top preference) sends an encrypted
// response. Before the fix, this panicked inside sendEncryptedRaw with a nil
// pointer dereference on sa.saKey.integ.OutputLen() and crashed the process.
func TestSendEncryptedRawAEADNoPanic(t *testing.T) {
	srv := NewServer(&Config{ListenAddr: "127.0.0.1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))

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

	key := randomKey(t, encrAesGcm16_256.KeyLen())
	saKey := &ikeSAKey{encr: encrAesGcm16_256, SK_er: key, SK_ei: key} // integ == nil, as selectIKEProposal sets for AEAD
	sa := &ikeSA{saKey: saKey, spiI: 1, spiR: 2}

	if err := srv.sendEncryptedRaw(srvConn, ueAddr, sa, message.INFORMATIONAL, 5, 0, []byte("hello AEAD"), false); err != nil {
		t.Fatalf("sendEncryptedRaw() with AES-GCM: error = %v", err)
	}

	buf := make([]byte, 4096)
	_ = ueConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := ueConn.Read(buf)
	if err != nil {
		t.Fatalf("UE did not receive a response: %v", err)
	}
	_, plain, err := decryptSK(saKey, buf[:n])
	if err != nil {
		t.Fatalf("decryptSK() error = %v", err)
	}
	if string(plain) != "hello AEAD" {
		t.Fatalf("decrypted plaintext = %q, want %q", plain, "hello AEAD")
	}
}

// TestSendEncryptedRequestAEADNoPanic covers the ePDG-initiated path (e.g.
// DPD probes) which had the identical defect in sendEncryptedRequest.
func TestSendEncryptedRequestAEADNoPanic(t *testing.T) {
	srv := NewServer(&Config{ListenAddr: "127.0.0.1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))

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

	key := randomKey(t, encrAesGcm16_128.KeyLen())
	saKey := &ikeSAKey{encr: encrAesGcm16_128, SK_er: key, SK_ei: key} // integ == nil
	sa := &ikeSA{saKey: saKey, spiI: 1, spiR: 2}

	if err := srv.sendEncryptedRequest(srvConn, ueAddr, sa, message.INFORMATIONAL, 7, 0, nil, false); err != nil {
		t.Fatalf("sendEncryptedRequest() with AES-GCM: error = %v", err)
	}

	buf := make([]byte, 4096)
	_ = ueConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ueConn.Read(buf); err != nil {
		t.Fatalf("UE did not receive a request: %v", err)
	}
}
