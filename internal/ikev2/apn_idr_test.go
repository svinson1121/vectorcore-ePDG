package ikev2

// Regression test for the TS 24.302 §7.4.1.1 gap found while reviewing the
// apn.default config: the ePDG must include the resolved APN (default or
// UE-provided) in the "IDr" payload of the final IKE_AUTH response, ID Type
// ID_FQDN — previously this implementation never sent an IDr payload at
// all in that response.

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/free5gc/ike/message"
)

func newTestServerForAPNIDr(t *testing.T) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(&Config{ListenAddr: "127.0.0.1"}, log)
}

// TestHandleAuthFinalEchoesAPNInIDr exercises handleAuthFinal end-to-end
// (loopback UDP, real encrypt/decrypt) with s2b/sessions/espProp all nil so
// only the response-building tail runs, and confirms the final response
// carries an IDr payload (ID_FQDN, content = the resolved APN).
func TestHandleAuthFinalEchoesAPNInIDr(t *testing.T) {
	srv := newTestServerForAPNIDr(t)

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
	msk := randomKey(t, 64)
	sa := &ikeSA{
		saKey:        saKey,
		msk:          msk,
		imsi:         "311435300070581",
		apn:          "ims",
		idiAuthBytes: buildIDAuthBytes(message.ID_RFC822_ADDR, []byte("0311435300070581@nai.epc.mnc435.mcc311.3gppnetwork.org")),
		initReqRaw:   []byte("fake-IKE_SA_INIT-request-bytes"),
		initRespRaw:  []byte("fake-IKE_SA_INIT-response-bytes"),
		nonceI:       []byte("fake-nonce-initiator-fake-nonce-initiator"),
		nonceR:       []byte("fake-nonce-responder-fake-nonce-responder"),
	}

	// Build a valid UE AUTH payload matching what handleAuthFinal expects.
	macedIDI := prfMAC(saKey.prf, saKey.SK_pi, sa.idiAuthBytes)
	initiatorSigned := concat(sa.initReqRaw, sa.nonceR, macedIDI)
	expectedAuth := computeEAPAUTH(saKey.prf, sa.msk, initiatorSigned)
	pl := &authPayloads{auth: &message.Authentication{AuthenticationData: expectedAuth}}

	hdr := &message.IKEHeader{MessageID: 2}
	srv.handleAuthFinal(srvConn, ueAddr, sa, hdr, pl, false)

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
		t.Fatal("final IKE_AUTH response missing IDr payload (TS 24.302 §7.4.1.1 requires the resolved APN here)")
	}
	if payloads.idr.IDType != message.ID_FQDN {
		t.Fatalf("IDr ID Type = %d, want %d (ID_FQDN)", payloads.idr.IDType, message.ID_FQDN)
	}
	if got := string(payloads.idr.IDData); got != sa.apn {
		t.Fatalf("IDr content = %q, want resolved APN %q", got, sa.apn)
	}
}
