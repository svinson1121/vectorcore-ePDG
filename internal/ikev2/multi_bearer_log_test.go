package ikev2

// Regression test: handleAuthRound1 must log when a UE's IKE_AUTH request
// includes the IKEV2_MULTIPLE_BEARER_PDN_CONNECTIVITY Notify (TS 24.302
// §8.1.2.3, type 42011), purely for observability — this ePDG does not
// implement the per-bearer CHILD_SA mechanism (finding #5), and not seeing
// this notify is not a spec violation (both UE and ePDG support are
// optional per §7.2.7.1/§7.4.6.1).

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/free5gc/ike/message"
)

func runRound1ForMultiBearerLog(t *testing.T, srv *Server, notifies []*message.Notification) {
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
		idi:      idi(message.ID_FQDN, "0234150999999999@nai.epc.mnc015.mcc234.3gppnetwork.org"),
		notifies: notifies,
	}
	hdr := &message.IKEHeader{MessageID: 1}

	// s.swm is nil, so this returns (via an AUTHENTICATION_FAILED notify)
	// right after the notify-detection/logging this test cares about.
	srv.handleAuthRound1(conn, remote, sa, hdr, pl, false)
}

func TestRound1LogsMultipleBearerPDNConnectivitySupport(t *testing.T) {
	var buf bytes.Buffer
	srv := newTestServerForAPNLog(t, &buf)

	runRound1ForMultiBearerLog(t, srv, []*message.Notification{
		{NotifyMessageType: notifyIKEv2MultipleBearerPDNConnectivity},
	})

	got := buf.String()
	if !strings.Contains(got, "UE supports IKEv2 multiple bearer PDN connectivity") {
		t.Fatalf("log output missing multiple-bearer-support message:\n%s", got)
	}
}

func TestRound1DoesNotLogMultipleBearerSupportWhenAbsent(t *testing.T) {
	var buf bytes.Buffer
	srv := newTestServerForAPNLog(t, &buf)

	runRound1ForMultiBearerLog(t, srv, nil)

	got := buf.String()
	if strings.Contains(got, "multiple bearer PDN connectivity") {
		t.Fatalf("log output unexpectedly mentions multiple bearer PDN connectivity when the UE didn't request it:\n%s", got)
	}
}
