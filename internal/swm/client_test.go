package swm

import (
	"context"
	"encoding/binary"
	"log/slog"
	"strings"
	"testing"
	"time"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/diameter"
)

func TestNewDERUsesSWmApplicationAndAuthRequestType(t *testing.T) {
	cfg := *config.Default()
	cfg.SWM.OriginHost = "epdg.example"
	cfg.SWM.OriginRealm = "example"
	cfg.SWM.DestinationRealm = "example"
	c := NewClient(cfg, slog.Default())
	msg := c.newDER("session", "311435300070580@nai.epc.mnc435.mcc311.3gppnetwork.org", "internet", []byte{2, 0, 0, 9, 1, 'i', 'd', '1', '2'})
	if msg.CommandCode != diameter.CommandDER || msg.AppID != config.SWMApplicationID {
		t.Fatalf("command/app = %d/%d", msg.CommandCode, msg.AppID)
	}
	if got, ok := diameter.AVPUint32(msg.AVPs, diameter.AVPAuthRequestType, 0); !ok || got != 1 {
		t.Fatalf("Auth-Request-Type = %d ok=%t", got, ok)
	}
	if got := diameter.AVPString(msg.AVPs, diameter.AVPUserName, 0); got != "311435300070580@nai.epc.mnc435.mcc311.3gppnetwork.org" {
		t.Fatalf("User-Name = %q", got)
	}
	if got := diameter.AVPString(msg.AVPs, diameter.AVPServiceSelection, 0); got != "internet" {
		t.Fatalf("Service-Selection = %q", got)
	}
}

// TestNewDERUsesFullNAINotBareIMSI is the regression test for audit finding
// #6's secondary defect: the DER's User-Name AVP (TS 29.273 clause 9.2.2.1.1)
// must carry the NAI exactly as presented — including the EAP-AKA pseudonym
// prefix digit ('2', TS 23.003 §19.3.5) — so the AAA server can resolve it.
// Substituting a bare IMSI (which doesn't exist yet for a pseudonym anyway)
// would break AAA-side identity resolution.
func TestNewDERUsesFullNAINotBareIMSI(t *testing.T) {
	cfg := *config.Default()
	cfg.SWM.OriginHost = "epdg.example"
	cfg.SWM.OriginRealm = "example"
	cfg.SWM.DestinationRealm = "example"
	c := NewClient(cfg, slog.Default())
	pseudonymNAI := "258405627015@nai.epc.mnc015.mcc234.3gppnetwork.org"
	msg := c.newDER("session", pseudonymNAI, "internet", []byte{2, 0, 0, 9, 1, 'i', 'd', '1', '2'})
	if got := diameter.AVPString(msg.AVPs, diameter.AVPUserName, 0); got != pseudonymNAI {
		t.Fatalf("User-Name = %q, want full pseudonym NAI %q", got, pseudonymNAI)
	}
}

func TestNewSTRUsesCommandSTRAndTerminationCause(t *testing.T) {
	cfg := *config.Default()
	cfg.SWM.OriginHost = "epdg.example"
	cfg.SWM.OriginRealm = "example"
	cfg.SWM.DestinationRealm = "aaa.example"
	c := NewClient(cfg, slog.Default())
	msg := c.newSTR("session-123", 1)
	if msg.CommandCode != diameter.CommandSTR || msg.AppID != config.SWMApplicationID {
		t.Fatalf("command/app = %d/%d", msg.CommandCode, msg.AppID)
	}
	if got := diameter.AVPString(msg.AVPs, diameter.AVPSessionID, 0); got != "session-123" {
		t.Fatalf("Session-Id = %q", got)
	}
	if got, ok := diameter.AVPUint32(msg.AVPs, diameter.AVPTerminationCause, 0); !ok || got != 1 {
		t.Fatalf("Termination-Cause = %d ok=%t", got, ok)
	}
	if got := diameter.AVPString(msg.AVPs, diameter.AVPDestinationRealm, 0); got != "aaa.example" {
		t.Fatalf("Destination-Realm = %q", got)
	}
}

func TestParseAPNProfileDirectConfiguration(t *testing.T) {
	ambr := diameter.GroupedAVP(diameter.AVPAMBR, diameter.Vendor3GPP,
		diameter.Uint32AVP(diameter.AVPMaxRequestedBandwidthUL, diameter.Vendor3GPP, 50000000),
		diameter.Uint32AVP(diameter.AVPMaxRequestedBandwidthDL, diameter.Vendor3GPP, 200000000),
	)
	apnCfg := diameter.GroupedAVP(diameter.AVPAPNConfiguration, diameter.Vendor3GPP,
		diameter.UTF8AVP(diameter.AVPServiceSelection, 0, "internet"),
		ambr,
	)
	profile := parseAPNProfile([]diameter.AVP{apnCfg}, "internet")
	if profile == nil {
		t.Fatalf("profile nil")
	}
	if profile.APN != "internet" || !profile.AMBRPresent {
		t.Fatalf("profile = %#v", profile)
	}
	if profile.AMBRUplink != 50000000 || profile.AMBRDownlink != 200000000 {
		t.Fatalf("AMBR = %d/%d", profile.AMBRUplink, profile.AMBRDownlink)
	}
}

func TestParseAPNProfileNestedNon3GPPUserData(t *testing.T) {
	ambr := diameter.GroupedAVP(diameter.AVPAMBR, diameter.Vendor3GPP,
		diameter.Uint32AVP(diameter.AVPMaxRequestedBandwidthUL, diameter.Vendor3GPP, 321),
		diameter.Uint32AVP(diameter.AVPMaxRequestedBandwidthDL, diameter.Vendor3GPP, 654),
	)
	apnCfg := diameter.GroupedAVP(diameter.AVPAPNConfiguration, diameter.Vendor3GPP,
		diameter.UTF8AVP(diameter.AVPServiceSelection, 0, "internet"),
		ambr,
	)
	userData := diameter.GroupedAVP(diameter.AVPNon3GPPUserData, diameter.Vendor3GPP, apnCfg)
	profile := parseAPNProfile([]diameter.AVP{userData}, "internet")
	if profile == nil {
		t.Fatalf("profile nil")
	}
	if profile.APN != "internet" || !profile.AMBRPresent {
		t.Fatalf("profile = %#v", profile)
	}
	if profile.AMBRUplink != 321 || profile.AMBRDownlink != 654 {
		t.Fatalf("AMBR = %d/%d", profile.AMBRUplink, profile.AMBRDownlink)
	}
}

func TestEAPResultExtractsMSK(t *testing.T) {
	cfg := *config.Default()
	c := NewClient(cfg, slog.Default())
	msk := make([]byte, 64)
	binary.BigEndian.PutUint32(msk[:4], 1)
	answer := diameter.Message{AVPs: []diameter.AVP{
		diameter.Uint32AVP(diameter.AVPResultCode, 0, diameterSuccess),
		diameter.OctetAVP(diameter.AVPEAPPayload, 0, diameter.FlagMandatory, []byte{3, 1, 0, 4}),
		diameter.OctetAVP(diameter.AVPEAPMasterSessionKey, 0, diameter.FlagMandatory, msk),
	}}
	res := c.eapResult(EAPRequest{IMSI: "311435300070580", APN: "internet"}, "session", answer)
	if res.State != EAPStateSuccess || !res.Allowed || len(res.MSK) != 64 {
		t.Fatalf("result = %#v", res)
	}
}

// TestEAPResultExtractsPermanentIdentity is the regression test for audit
// finding #6: when the UE authenticated with a pseudonym or fast
// re-authentication identity, the ePDG has no locally-known IMSI, and the
// DEA's User-Name AVP (TS 29.273 clause 9.2.2.1.2, "Permanent User
// Identity" — root-NAI-formatted, no leading auth-method digit) is the only
// authoritative source for one.
func TestEAPResultExtractsPermanentIdentity(t *testing.T) {
	cfg := *config.Default()
	c := NewClient(cfg, slog.Default())
	msk := make([]byte, 64)
	answer := diameter.Message{AVPs: []diameter.AVP{
		diameter.Uint32AVP(diameter.AVPResultCode, 0, diameterSuccess),
		diameter.OctetAVP(diameter.AVPEAPPayload, 0, diameter.FlagMandatory, []byte{3, 1, 0, 4}),
		diameter.OctetAVP(diameter.AVPEAPMasterSessionKey, 0, diameter.FlagMandatory, msk),
		diameter.UTF8AVP(diameter.AVPUserName, 0, "234150999999999@nai.epc.mnc015.mcc234.3gppnetwork.org"),
	}}
	// The UE presented a pseudonym, not its IMSI — req.IMSI is empty.
	req := EAPRequest{NAI: "258405627015@nai.epc.mnc015.mcc234.3gppnetwork.org", APN: "internet"}
	res := c.eapResult(req, "session", answer)
	if res.State != EAPStateSuccess || !res.Allowed {
		t.Fatalf("result = %#v", res)
	}
	if res.PermanentIdentity != "234150999999999" {
		t.Fatalf("PermanentIdentity = %q, want IMSI resolved from DEA User-Name AVP", res.PermanentIdentity)
	}
}

func TestEAPResultPermanentIdentityEmptyWithoutUserNameAVP(t *testing.T) {
	cfg := *config.Default()
	c := NewClient(cfg, slog.Default())
	msk := make([]byte, 64)
	answer := diameter.Message{AVPs: []diameter.AVP{
		diameter.Uint32AVP(diameter.AVPResultCode, 0, diameterSuccess),
		diameter.OctetAVP(diameter.AVPEAPPayload, 0, diameter.FlagMandatory, []byte{3, 1, 0, 4}),
		diameter.OctetAVP(diameter.AVPEAPMasterSessionKey, 0, diameter.FlagMandatory, msk),
	}}
	res := c.eapResult(EAPRequest{IMSI: "311435300070580", APN: "internet"}, "session", answer)
	if res.PermanentIdentity != "" {
		t.Fatalf("PermanentIdentity = %q, want empty when DEA omits User-Name", res.PermanentIdentity)
	}
}

func TestEAPResultPermanentIdentityRejectsMalformedUserName(t *testing.T) {
	cfg := *config.Default()
	c := NewClient(cfg, slog.Default())
	msk := make([]byte, 64)
	answer := diameter.Message{AVPs: []diameter.AVP{
		diameter.Uint32AVP(diameter.AVPResultCode, 0, diameterSuccess),
		diameter.OctetAVP(diameter.AVPEAPPayload, 0, diameter.FlagMandatory, []byte{3, 1, 0, 4}),
		diameter.OctetAVP(diameter.AVPEAPMasterSessionKey, 0, diameter.FlagMandatory, msk),
		diameter.UTF8AVP(diameter.AVPUserName, 0, "not-an-imsi@nai.epc.mnc015.mcc234.3gppnetwork.org"),
	}}
	res := c.eapResult(EAPRequest{APN: "internet"}, "session", answer)
	if res.PermanentIdentity != "" {
		t.Fatalf("PermanentIdentity = %q, want empty for malformed User-Name", res.PermanentIdentity)
	}
}

func TestExchangeEAPNoLongerRequiresIMSI(t *testing.T) {
	cfg := *config.Default()
	c := NewClient(cfg, slog.Default())
	// No peer connection is started; use a short deadline so the unrelated
	// "waitOpen" timeout (past the IMSI/NAI validation this test checks)
	// resolves quickly instead of the client's full 10s internal timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.ExchangeEAP(ctx, EAPRequest{
		NAI: "258405627015@nai.epc.mnc015.mcc234.3gppnetwork.org",
		APN: "internet", EAPPayload: []byte{1, 1, 0, 4},
	})
	if err != nil && strings.Contains(err.Error(), "IMSI") {
		t.Fatalf("ExchangeEAP() with empty IMSI but valid NAI: unexpected IMSI-related error: %v", err)
	}
}

func TestExchangeEAPRequiresNAI(t *testing.T) {
	cfg := *config.Default()
	c := NewClient(cfg, slog.Default())
	_, err := c.ExchangeEAP(context.Background(), EAPRequest{APN: "internet", EAPPayload: []byte{1, 1, 0, 4}})
	if err == nil || !strings.Contains(err.Error(), "NAI") {
		t.Fatalf("ExchangeEAP() with empty NAI: err = %v, want error mentioning NAI", err)
	}
}
