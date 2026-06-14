package swm

import (
	"encoding/binary"
	"log/slog"
	"testing"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/diameter"
)

func TestNewDERUsesSWmApplicationAndAuthRequestType(t *testing.T) {
	cfg := *config.Default()
	cfg.SWM.OriginHost = "epdg.example"
	cfg.SWM.OriginRealm = "example"
	cfg.SWM.DestinationRealm = "example"
	c := NewClient(cfg, slog.Default())
	msg := c.newDER("session", "311435300070580", "internet", []byte{2, 0, 0, 9, 1, 'i', 'd', '1', '2'})
	if msg.CommandCode != diameter.CommandDER || msg.AppID != config.SWMApplicationID {
		t.Fatalf("command/app = %d/%d", msg.CommandCode, msg.AppID)
	}
	if got, ok := diameter.AVPUint32(msg.AVPs, diameter.AVPAuthRequestType, 0); !ok || got != 1 {
		t.Fatalf("Auth-Request-Type = %d ok=%t", got, ok)
	}
	if got := diameter.AVPString(msg.AVPs, diameter.AVPUserName, 0); got != "311435300070580" {
		t.Fatalf("User-Name = %q", got)
	}
	if got := diameter.AVPString(msg.AVPs, diameter.AVPServiceSelection, 0); got != "internet" {
		t.Fatalf("Service-Selection = %q", got)
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
