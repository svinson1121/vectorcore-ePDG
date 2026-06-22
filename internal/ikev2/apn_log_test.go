package ikev2

// Regression test: handleAuthRound1 must log which APN it resolved and
// whether that came from the UE's IDr or the configured default, so an
// operator can see from logs alone how often UEs actually send an APN
// (TS 24.302 §7.2.2.1 treats omitting it as a normal, conformant request
// for the default APN).

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/free5gc/ike/message"
)

func newTestServerForAPNLog(t *testing.T, buf *bytes.Buffer) *Server {
	t.Helper()
	log := slog.New(slog.NewTextHandler(buf, nil))
	return NewServer(&Config{ListenAddr: "127.0.0.1"}, log)
}

func runRound1ForAPNLog(t *testing.T, srv *Server, idrPL *message.IdentificationResponder) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	key := randomKey(t, encrAesCbc256.KeyLen())
	integKey := randomKey(t, integSha256_128.KeyLen())
	sa := &ikeSA{
		saKey: &ikeSAKey{
			encr: encrAesCbc256, integ: integSha256_128,
			prf:   prfSha256,
			SK_er: key, SK_ei: key, SK_ar: integKey, SK_ai: integKey,
			SK_pr: randomKey(t, 32), SK_pi: randomKey(t, 32),
		},
		initRespRaw: []byte("fake-IKE_SA_INIT-response-bytes"),
	}
	pl := &authPayloads{
		idi: idi(message.ID_FQDN, "0234150999999999@nai.epc.mnc015.mcc234.3gppnetwork.org"),
		idr: idrPL,
	}
	hdr := &message.IKEHeader{MessageID: 1}

	// s.swm is nil, so this returns (via an AUTHENTICATION_FAILED notify)
	// right after the APN resolution/logging this test cares about.
	srv.handleAuthRound1(conn, remote, sa, hdr, pl, false)
}

func TestRound1LogsUERequestedAPN(t *testing.T) {
	var buf bytes.Buffer
	srv := newTestServerForAPNLog(t, &buf)

	runRound1ForAPNLog(t, srv, &message.IdentificationResponder{
		IDType: message.ID_FQDN,
		IDData: []byte("voice.mnc015.mcc234.gprs"),
	})

	got := buf.String()
	if !strings.Contains(got, "UE requested APN") {
		t.Fatalf("log output missing UE-requested-APN message:\n%s", got)
	}
	if !strings.Contains(got, "apn=voice") {
		t.Fatalf("log output missing requested apn=voice:\n%s", got)
	}
	if strings.Contains(got, "using default") {
		t.Fatalf("log output incorrectly mentions defaulting for a UE-requested APN:\n%s", got)
	}
}

func TestRound1LogsDefaultAPNWhenUEOmitsIt(t *testing.T) {
	var buf bytes.Buffer
	srv := newTestServerForAPNLog(t, &buf)

	runRound1ForAPNLog(t, srv, nil) // UE omitted IDr entirely.

	got := buf.String()
	if !strings.Contains(got, "did not request an APN, using default") {
		t.Fatalf("log output missing default-APN message:\n%s", got)
	}
	if !strings.Contains(got, "default_apn=ims") {
		t.Fatalf("log output missing default_apn=ims (no apn.default configured in this test):\n%s", got)
	}
}
