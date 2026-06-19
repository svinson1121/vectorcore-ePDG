package ikev2

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestECDHGroupRoundTrip verifies both sides of an ECDH exchange agree on the
// shared secret, for both IANA groups added in docs/ipsec-gaps.md (19, 20).
func TestECDHGroupRoundTrip(t *testing.T) {
	groups := []struct {
		name string
		g    *ecdhGroup
	}{
		{"P-256 (group 19)", ecdh256Group},
		{"P-384 (group 20)", ecdh384Group},
	}

	for _, tt := range groups {
		t.Run(tt.name, func(t *testing.T) {
			privA, err := tt.g.GeneratePrivateKey()
			if err != nil {
				t.Fatalf("GeneratePrivateKey() (side A): %v", err)
			}
			pubA := tt.g.PublicKey(privA)
			if len(pubA) != tt.g.ByteLen() {
				t.Fatalf("PublicKey() length = %d, want %d (IKEv2 KE payload size for this group)", len(pubA), tt.g.ByteLen())
			}

			privB, err := tt.g.GeneratePrivateKey()
			if err != nil {
				t.Fatalf("GeneratePrivateKey() (side B): %v", err)
			}
			pubB := tt.g.PublicKey(privB)

			sharedA, err := tt.g.SharedKey(privA, pubB)
			if err != nil {
				t.Fatalf("SharedKey() (side A): %v", err)
			}
			sharedB, err := tt.g.SharedKey(privB, pubA)
			if err != nil {
				t.Fatalf("SharedKey() (side B): %v", err)
			}
			if !bytes.Equal(sharedA, sharedB) {
				t.Fatalf("shared secrets disagree: A=%x B=%x", sharedA, sharedB)
			}
		})
	}
}

// TestECDHGroupRejectsBadPeerLength ensures a malformed KE payload (wrong
// length for the negotiated group) is rejected rather than silently
// truncated/zero-padded.
func TestECDHGroupRejectsBadPeerLength(t *testing.T) {
	priv, err := ecdh256Group.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey(): %v", err)
	}
	if _, err := ecdh256Group.SharedKey(priv, make([]byte, 10)); err == nil {
		t.Fatal("SharedKey() with wrong-length peer public value: want error, got nil")
	}
}

// TestDHGroupByIDIncludesECDH confirms dhGroupByID resolves the new IANA
// group IDs to the ECDH implementations, matching the TransformID each
// reports back (used to validate the KE payload's stated group on the wire).
func TestDHGroupByIDIncludesECDH(t *testing.T) {
	if g := dhGroupByID(dh256RandomECP); g == nil || g.TransformID() != dh256RandomECP {
		t.Fatalf("dhGroupByID(19) = %v, want ecdh256Group", g)
	}
	if g := dhGroupByID(dh384RandomECP); g == nil || g.TransformID() != dh384RandomECP {
		t.Fatalf("dhGroupByID(20) = %v, want ecdh384Group", g)
	}
}

// randomKey returns n cryptographically random bytes, failing the test on error.
func randomKey(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

// TestEncryptDecryptSKCBCRoundTrip guards the pre-existing AES-CBC+HMAC SK
// payload path against regressions from the AEAD dispatch added to
// encryptSK/decryptSK for docs/ipsec-gaps.md Gap 2.
func TestEncryptDecryptSKCBCRoundTrip(t *testing.T) {
	key := randomKey(t, encrAesCbc256.KeyLen())
	integKey := randomKey(t, integSha256_128.KeyLen())
	saKey := &ikeSAKey{
		encr: encrAesCbc256, integ: integSha256_128,
		SK_er: key, SK_ei: key, SK_ar: integKey, SK_ai: integKey,
	}

	header := make([]byte, 28)
	plaintext := []byte("legacy CBC+HMAC inner payloads, arbitrary length")

	msg, err := encryptSK(saKey, 1, plaintext, header)
	if err != nil {
		t.Fatalf("encryptSK() error = %v", err)
	}
	_, got, err := decryptSK(saKey, msg)
	if err != nil {
		t.Fatalf("decryptSK() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decryptSK() plaintext = %q, want %q", got, plaintext)
	}
}

// TestEncryptDecryptSKAEADRoundTrip covers docs/ipsec-gaps.md Gap 2 (IKE SA
// AES-GCM): encryptSK/decryptSK must round-trip for both key sizes using the
// combined-mode (no separate SK_ai/SK_ar) path.
func TestEncryptDecryptSKAEADRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		encr *encrAlg
	}{
		{"AES-GCM-128", encrAesGcm16_128},
		{"AES-GCM-256", encrAesGcm16_256},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := randomKey(t, tt.encr.KeyLen())
			// encryptSK always uses SK_er and decryptSK always uses SK_ei
			// (production: responder-send / initiator-receive keys, which
			// differ). Setting them equal here tests the wire format and
			// AEAD correctness, not key separation between directions.
			saKey := &ikeSAKey{encr: tt.encr, SK_er: key, SK_ei: key}

			header := make([]byte, 28)
			for i := range header {
				header[i] = byte(i) // non-zero, distinguishable AAD bytes
			}
			plaintext := []byte("IKE_AUTH inner payloads, arbitrary length content")

			msg, err := encryptSK(saKey, 1, plaintext, header)
			if err != nil {
				t.Fatalf("encryptSK() error = %v", err)
			}
			nextPayload, got, err := decryptSK(saKey, msg)
			if err != nil {
				t.Fatalf("decryptSK() error = %v", err)
			}
			if nextPayload != 1 {
				t.Fatalf("decryptSK() innerNextPayload = %d, want 1", nextPayload)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("decryptSK() plaintext = %q, want %q", got, plaintext)
			}
		})
	}
}

// TestDecryptSKAEADTamperDetection ensures a corrupted ciphertext/tag is
// rejected rather than silently accepted or producing garbage plaintext.
func TestDecryptSKAEADTamperDetection(t *testing.T) {
	key := randomKey(t, encrAesGcm16_256.KeyLen())
	saKey := &ikeSAKey{encr: encrAesGcm16_256, SK_er: key, SK_ei: key}

	header := make([]byte, 28)
	msg, err := encryptSK(saKey, 1, []byte("payload"), header)
	if err != nil {
		t.Fatalf("encryptSK() error = %v", err)
	}

	tampered := append([]byte{}, msg...)
	tampered[len(tampered)-1] ^= 0xFF // flip a bit in the GCM tag
	if _, _, err := decryptSK(saKey, tampered); err == nil {
		t.Fatal("decryptSK() with tampered ciphertext: want error, got nil")
	}
}
