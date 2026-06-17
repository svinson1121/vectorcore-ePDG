package s2b

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/pco"

	gtpv2ref "github.com/wmnsk/go-gtp/gtpv2"
	ieref "github.com/wmnsk/go-gtp/gtpv2/ie"
	msgref "github.com/wmnsk/go-gtp/gtpv2/message"
)

func testConfig() config.Config {
	cfg := *config.Default()
	cfg.EPDG.MCC = "311"
	cfg.EPDG.MNC = "435"
	cfg.EPDG.MNCLength = 3
	cfg.GTP.LocalGTPC = "10.90.250.55"
	cfg.GTP.LocalGTPU = "10.90.250.55"
	cfg.GTP.PGWGTPC = "10.90.250.92"
	return cfg
}

func TestCreateBearerResponseUsesS2bEPDGDataFTEID(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	result := CreateBearerResult{
		Accepted: true,
		Cause:    causeRequestAccepted,
		Bearers: []CreateBearerBearerResult{{
			EBI:           6,
			Accepted:      true,
			Cause:         causeRequestAccepted,
			LocalUserTEID: 0x11223344,
			LocalUserIP:   net.ParseIP("10.90.250.55"),
		}},
	}
	resp := c.createBearerResponseMessage(message{Type: msgCreateBearerReq, TEID: 0x694b5b73, HasTEID: true, Sequence: 260612}, result)
	ies, err := decodeIEs(resp.Payload)
	if err != nil {
		t.Fatalf("decodeIEs() error = %v", err)
	}
	bc, ok := findIE(ies, ieBearerContext, 0)
	if !ok {
		t.Fatal("missing bearer context")
	}
	children, err := decodeIEs(bc.Payload)
	if err != nil {
		t.Fatalf("decode bearer context: %v", err)
	}
	fteid, ok := findIE(children, ieFTEID, instanceCreateBearerResponseS2bEPDGDataFTEID)
	if !ok {
		t.Fatalf("missing S2b ePDG data F-TEID instance %d", instanceCreateBearerResponseS2bEPDGDataFTEID)
	}
	if fteid.Instance != instanceCreateBearerResponseS2bEPDGDataFTEID {
		t.Fatalf("F-TEID instance = %d, want %d", fteid.Instance, instanceCreateBearerResponseS2bEPDGDataFTEID)
	}
	if iface, teid, ip, ok := parseFTEID(fteid); !ok || iface != ifaceS2BePDGGTPU || teid != 0x11223344 || !ip.Equal(net.ParseIP("10.90.250.55")) {
		t.Fatalf("F-TEID iface=%d teid=%#x ip=%s ok=%t", iface, teid, ip, ok)
	}
	// Wire-format check: type=0x57, len=0x0009, instance=0x08, flags=0x9f (V4+iface31)
	if got := hex.EncodeToString(fteid.encode()[:5]); got != "570009089f" {
		t.Fatalf("F-TEID prefix = %s, want 570009089f", got)
	}
}

func TestCreateBearerResponseMatchesGoGTPS2bReference(t *testing.T) {
	if gtpv2ref.IFTypeS2bUePDGGTPU != ifaceS2BePDGGTPU {
		t.Fatalf("go-gtp S2b ePDG GTP-U interface = %d, local = %d", gtpv2ref.IFTypeS2bUePDGGTPU, ifaceS2BePDGGTPU)
	}

	c := NewClient(testConfig(), slog.Default())
	req := message{Type: msgCreateBearerReq, TEID: 0x487e8ee6, HasTEID: true, Sequence: 126978}
	bearers := []CreateBearerBearerResult{
		{EBI: 6, Accepted: true, Cause: causeRequestAccepted, LocalUserTEID: 0xd32f5697, LocalUserIP: net.ParseIP("10.90.250.55")},
		{EBI: 7, Accepted: true, Cause: causeRequestAccepted, LocalUserTEID: 0xd295f438, LocalUserIP: net.ParseIP("10.90.250.55")},
	}

	local := c.createBearerResponseMessage(req, CreateBearerResult{
		Accepted: true,
		Cause:    causeRequestAccepted,
		Bearers:  bearers,
	})
	localBytes, err := local.encode()
	if err != nil {
		t.Fatalf("local encode: %v", err)
	}
	refBytes := goGTPReferenceCreateBearerResponse(t, req.TEID, req.Sequence, bearers)

	localMsg, err := decodeMessage(localBytes)
	if err != nil {
		t.Fatalf("decode local response: %v", err)
	}
	refMsg, err := decodeMessage(refBytes)
	if err != nil {
		t.Fatalf("decode go-gtp response: %v", err)
	}
	if localMsg.Type != msgCreateBearerResp || refMsg.Type != msgCreateBearerResp {
		t.Fatalf("message types local=%d ref=%d", localMsg.Type, refMsg.Type)
	}
	if localMsg.TEID != req.TEID || refMsg.TEID != req.TEID || localMsg.Sequence != req.Sequence || refMsg.Sequence != req.Sequence {
		t.Fatalf("transaction mismatch local teid=%#x seq=%d ref teid=%#x seq=%d", localMsg.TEID, localMsg.Sequence, refMsg.TEID, refMsg.Sequence)
	}

	assertCreateBearerResponseBearerContexts(t, "local", localMsg.Payload, bearers)
	assertCreateBearerResponseBearerContexts(t, "go-gtp", refMsg.Payload, bearers)
}

func goGTPReferenceCreateBearerResponse(t *testing.T, teid, seq uint32, bearers []CreateBearerBearerResult) []byte {
	t.Helper()

	ies := []*ieref.IE{
		ieref.NewCause(gtpv2ref.CauseRequestAccepted, 0, 0, 0, nil),
	}
	for _, br := range bearers {
		// Build the same S2b Bearer Context shape VectorCore sends: Cause,
		// allocated dedicated EBI, and local ePDG S2b-U F-TEID.
		ies = append(ies, ieref.NewBearerContext(
			ieref.NewCause(br.Cause, 0, 0, 0, nil),
			ieref.NewEPSBearerID(br.EBI),
			ieref.NewFullyQualifiedTEID(gtpv2ref.IFTypeS2bUePDGGTPU, br.LocalUserTEID, br.LocalUserIP.String(), "").
				WithInstance(instanceCreateBearerResponseS2bEPDGDataFTEID),
		))
	}
	msg := msgref.NewCreateBearerResponse(teid, seq, ies...)
	b, err := msg.Marshal()
	if err != nil {
		t.Fatalf("go-gtp reference encode: %v", err)
	}
	return b
}

func assertCreateBearerResponseBearerContexts(t *testing.T, label string, payload []byte, bearers []CreateBearerBearerResult) {
	t.Helper()

	ies, err := decodeIEs(payload)
	if err != nil {
		t.Fatalf("%s decode payload: %v", label, err)
	}
	if cause, ok := findIE(ies, ieCause, 0); !ok || len(cause.Payload) < 1 || cause.Payload[0] != causeRequestAccepted {
		t.Fatalf("%s missing accepted top-level cause", label)
	}

	var contexts []ie
	for _, top := range ies {
		if top.Type == ieBearerContext {
			contexts = append(contexts, top)
		}
	}
	if len(contexts) != len(bearers) {
		t.Fatalf("%s bearer context count = %d, want %d", label, len(contexts), len(bearers))
	}

	for i, bc := range contexts {
		children, err := decodeIEs(bc.Payload)
		if err != nil {
			t.Fatalf("%s bearer %d decode: %v", label, i, err)
		}
		if got, want := len(bc.Payload), groupedPayloadLen(children); got != want {
			t.Fatalf("%s bearer %d grouped length = %d, child length sum = %d", label, i, got, want)
		}

		cause, ok := findIE(children, ieCause, 0)
		if !ok || len(cause.Payload) < 1 || cause.Payload[0] != causeRequestAccepted {
			t.Fatalf("%s bearer %d missing accepted cause", label, i)
		}
		ebiIE, ok := findIE(children, ieEBI, 0)
		if !ok {
			t.Fatalf("%s bearer %d missing EBI", label, i)
		}
		ebi, err := parseEBI(ebiIE.Payload)
		if err != nil || ebi != bearers[i].EBI {
			t.Fatalf("%s bearer %d EBI=%d err=%v, want %d", label, i, ebi, err, bearers[i].EBI)
		}
		fteid, ok := findIE(children, ieFTEID, instanceCreateBearerResponseS2bEPDGDataFTEID)
		if !ok {
			t.Fatalf("%s bearer %d missing S2b ePDG data F-TEID instance %d", label, i, instanceCreateBearerResponseS2bEPDGDataFTEID)
		}
		iface, teid, ip, ok := parseFTEID(fteid)
		if !ok || iface != ifaceS2BePDGGTPU || teid != bearers[i].LocalUserTEID || !ip.Equal(bearers[i].LocalUserIP) {
			t.Fatalf("%s bearer %d F-TEID iface=%d teid=%#x ip=%s ok=%t", label, i, iface, teid, ip, ok)
		}
	}
}

func groupedPayloadLen(ies []ie) int {
	n := 0
	for _, e := range ies {
		n += len(e.encode())
	}
	return n
}

func TestCreateBearerResponseCacheReturnsSameBytes(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	peer := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30064}
	req := message{Type: msgCreateBearerReq, TEID: 0x694b5b73, HasTEID: true, Sequence: 260612}
	resp := c.createBearerResponseMessage(req, CreateBearerResult{
		Accepted: true,
		Cause:    causeRequestAccepted,
		Bearers: []CreateBearerBearerResult{{
			EBI:           6,
			Accepted:      true,
			Cause:         causeRequestAccepted,
			LocalUserTEID: 0x11223344,
			LocalUserIP:   net.ParseIP("10.90.250.55"),
		}},
	})
	encoded, err := resp.encode()
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	key := createBearerCacheKey(peer, req)
	c.cacheCreateBearerResponse(key, encoded, []uint8{6})
	cached, ok := c.cachedCreateBearerResponse(key)
	if !ok {
		t.Fatal("cached response not found")
	}
	if string(cached.Encoded) != string(encoded) || len(cached.BearerEBI) != 1 || cached.BearerEBI[0] != 6 {
		t.Fatalf("cached = %+v encoded=%x", cached, encoded)
	}
}

func TestCreateSessionPayloadUsesS2bInterfaceTypes(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	payload := c.createSessionPayload(CreateSessionRequest{
		IMSI:         "311435300070580",
		APN:          "internet",
		AMBRUplink:   50000000,
		AMBRDownlink: 200000000,
	}, 50000, 200000, 0x01020304, 0x05060708)
	ies, err := decodeIEs(payload)
	if err != nil {
		t.Fatalf("decodeIEs() error = %v", err)
	}
	if rat, ok := findIE(ies, ieRATType, 0); !ok || len(rat.Payload) != 1 || rat.Payload[0] != ratTypeWLAN {
		t.Fatalf("RAT-Type = %#v ok=%t", rat.Payload, ok)
	}
	if sender, ok := findIE(ies, ieFTEID, 0); !ok {
		t.Fatal("missing sender F-TEID")
	} else if iface, teid, ip, ok := parseFTEID(sender); !ok || iface != ifaceS2BePDGGTPC || teid != 0x01020304 || !ip.Equal(net.ParseIP("10.90.250.55")) {
		t.Fatalf("sender F-TEID iface=%d teid=0x%x ip=%s ok=%t", iface, teid, ip, ok)
	}
	paa, ok := findIE(ies, iePAA, 0)
	if !ok || string(paa.Payload) != string([]byte{pdnTypeIPv4, 0, 0, 0, 0}) {
		t.Fatalf("PAA request = % x ok=%t", paa.Payload, ok)
	}
	ambr, ok := findIE(ies, ieAMBR, 0)
	if !ok || binary.BigEndian.Uint32(ambr.Payload[0:4]) != 50000 || binary.BigEndian.Uint32(ambr.Payload[4:8]) != 200000 {
		t.Fatalf("AMBR = % x ok=%t", ambr.Payload, ok)
	}
	bearer, ok := findIE(ies, ieBearerContext, 0)
	if !ok {
		t.Fatal("missing bearer context")
	}
	children, err := decodeIEs(bearer.Payload)
	if err != nil {
		t.Fatalf("decode bearer error = %v", err)
	}
	if bearerFTEID, ok := findIE(children, ieFTEID, 5); !ok {
		t.Fatal("missing S2b-U ePDG F-TEID instance 5")
	} else if iface, teid, ip, ok := parseFTEID(bearerFTEID); !ok || iface != ifaceS2BePDGGTPU || teid != 0x05060708 || !ip.Equal(net.ParseIP("10.90.250.55")) {
		t.Fatalf("bearer F-TEID iface=%d teid=0x%x ip=%s ok=%t", iface, teid, ip, ok)
	}
}

func TestParseCreateSessionResponse(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	resp := message{
		Type:     msgCreateSessionResp,
		TEID:     0x01020304,
		HasTEID:  true,
		Sequence: 1,
		Payload: encodeIEs(
			ie{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
			ie{Type: iePAA, Payload: []byte{pdnTypeIPv4, 172, 20, 0, 9}},
			fteidIE(1, ifaceS2BPGWGTPC, 0x11111111, net.ParseIP("10.90.250.92")),
			recoveryIE(7),
			ie{Type: ieBearerContext, Payload: encodeIEs(
				ie{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
				uint8IE(ieEBI, 5),
				fteidIE(2, ifaceS2BPGWGTPU, 0x22222222, net.ParseIP("10.90.250.92")),
			)},
		),
	}
	result, err := c.parseCreateSessionResponse(resp, 0x01020304, 0x05060708)
	if err != nil {
		t.Fatalf("parseCreateSessionResponse() error = %v", err)
	}
	if !result.PAA.Equal(net.ParseIP("172.20.0.9")) || result.PGWControlTEID != 0x11111111 || result.PGWUserTEID != 0x22222222 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.EBI != 5 || result.PGWRecovery != 7 || result.LocalUserTEID != 0x05060708 {
		t.Fatalf("unexpected bearer/session fields: %#v", result)
	}
}

func TestDeleteSessionCauseErrorClassifiesContextNotFound(t *testing.T) {
	err := &DeleteSessionCauseError{Cause: causeContextNotFound}
	if !IsContextNotFound(err) {
		t.Fatal("IsContextNotFound() = false")
	}
	cause, name, ok := DeleteCause(err)
	if !ok || cause != causeContextNotFound || name != "Context Not Found" {
		t.Fatalf("DeleteCause() = %d %q %t", cause, name, ok)
	}
	wrapped := errors.New("other")
	if _, _, ok := DeleteCause(wrapped); ok {
		t.Fatal("DeleteCause() found cause in plain error")
	}
}

func TestCreateSessionPayloadIncludesConfiguredPCORequest(t *testing.T) {
	cfg := testConfig()
	cfg.PCO.RequestDNSv4 = true
	cfg.PCO.RequestDNSv6 = true
	c := NewClient(cfg, slog.Default())
	payload := c.createSessionPayload(CreateSessionRequest{
		IMSI: "311435300070580",
		APN:  "internet",
	}, 0, 0, 0x01020304, 0x05060708)
	ies, err := decodeIEs(payload)
	if err != nil {
		t.Fatalf("decodeIEs() error = %v", err)
	}
	raw, ok := findIE(ies, iePCO, 0)
	if !ok {
		t.Fatal("missing PCO IE")
	}
	decoded, err := pco.Decode(raw.Payload, true)
	if err != nil {
		t.Fatalf("pco Decode() error = %v", err)
	}
	ids := pco.ProtocolIDs(decoded.PCO.Containers)
	if len(ids) != 2 || ids[0] != "0x0003" || ids[1] != "0x000d" {
		t.Fatalf("PCO request IDs = %v", ids)
	}
}

func TestParseCreateSessionResponseDecodesPCO(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	resp := message{
		Type:     msgCreateSessionResp,
		TEID:     0x01020304,
		HasTEID:  true,
		Sequence: 1,
		Payload: encodeIEs(
			ie{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
			ie{Type: iePAA, Payload: []byte{pdnTypeIPv4, 172, 20, 0, 9}},
			fteidIE(1, ifaceS2BPGWGTPC, 0x11111111, net.ParseIP("10.90.250.92")),
			ie{Type: iePCO, Payload: []byte{0x80, 0x00, 0x0d, 0x04, 8, 8, 8, 8}},
			ie{Type: ieBearerContext, Payload: encodeIEs(
				ie{Type: ieCause, Payload: []byte{causeRequestAccepted, 0}},
				uint8IE(ieEBI, 5),
				fteidIE(2, ifaceS2BPGWGTPU, 0x22222222, net.ParseIP("10.90.250.92")),
			)},
		),
	}
	result, err := c.parseCreateSessionResponse(resp, 0x01020304, 0x05060708)
	if err != nil {
		t.Fatalf("parseCreateSessionResponse() error = %v", err)
	}
	if result.ResponsePCO == nil || len(result.ResponsePCO.DNSv4) != 1 || !result.ResponsePCO.DNSv4[0].Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("ResponsePCO = %#v", result.ResponsePCO)
	}
}

func TestGTPAMBRConvertsBpsToKbps(t *testing.T) {
	ul, dl, err := gtpAMBR(50000001, 200000999)
	if err != nil {
		t.Fatalf("gtpAMBR() error = %v", err)
	}
	if ul != 50001 || dl != 200001 {
		t.Fatalf("AMBR = %d/%d", ul, dl)
	}
}

func TestDeleteSessionPayloadIncludesSenderFTEID(t *testing.T) {
	c := NewClient(testConfig(), slog.Default())
	payload := encodeIEs(
		uint8IE(ieEBI, 5),
		fteidIE(0, ifaceS2BePDGGTPC, 0x01020304, net.ParseIP(c.cfg.GTP.LocalGTPC)),
	)
	ies, err := decodeIEs(payload)
	if err != nil {
		t.Fatalf("decodeIEs() error = %v", err)
	}
	if ebi, ok := findIE(ies, ieEBI, 0); !ok || len(ebi.Payload) != 1 || ebi.Payload[0] != 5 {
		t.Fatalf("EBI = % x ok=%t", ebi.Payload, ok)
	}
	sender, ok := findIE(ies, ieFTEID, 0)
	if !ok {
		t.Fatal("missing sender F-TEID")
	}
	if iface, teid, ip, ok := parseFTEID(sender); !ok || iface != ifaceS2BePDGGTPC || teid != 0x01020304 || !ip.Equal(net.ParseIP("10.90.250.55")) {
		t.Fatalf("sender F-TEID iface=%d teid=0x%x ip=%s ok=%t", iface, teid, ip, ok)
	}
}

func TestParseCreateBearerRequestParsesGroupedBearerContexts(t *testing.T) {
	req := message{
		Type:     msgCreateBearerReq,
		TEID:     0xdeadbeef,
		HasTEID:  true,
		Sequence: 99,
		Payload: encodeIEs(
			ebiValueIE(5),
			ie{Type: ieBearerContext, Instance: 0, Payload: encodeIEs(
				ebiValueIE(6),
				ie{Type: ieTFT, Payload: []byte{0x21, 0x01, 0x02}},
				fteidIE(2, ifaceS2BPGWGTPU, 0x11111111, net.ParseIP("10.90.250.92")),
				ie{Type: ieBearerQoS, Payload: []byte{0, 1}},
				ie{Type: ieChargingID, Payload: []byte{0, 0, 0, 9}},
			)},
			ie{Type: ieBearerContext, Instance: 1, Payload: encodeIEs(
				ebiValueIE(7),
				ie{Type: ieTFT, Payload: []byte{0x21, 0x03, 0x04}},
				fteidIE(2, ifaceS2BPGWGTPU, 0x22222222, net.ParseIP("10.90.250.92")),
				ie{Type: ieBearerQoS, Payload: []byte{0, 2}},
				ie{Type: ieChargingID, Payload: []byte{0, 0, 0, 10}},
			)},
		),
	}
	event, err := parseCreateBearerRequest(req, &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30048})
	if err != nil {
		t.Fatalf("parseCreateBearerRequest() error = %v", err)
	}
	if len(event.Bearers) != 2 {
		t.Fatalf("bearer count = %d", len(event.Bearers))
	}
	if event.Bearers[0].EBI != 6 || event.Bearers[0].PGWUserTEID != 0x11111111 || event.Bearers[0].QCI != 1 || !event.Bearers[0].HasBearerQoS || len(event.Bearers[0].TFTRaw) == 0 || !event.Bearers[0].HasChargingID {
		t.Fatalf("bearer[0] = %+v", event.Bearers[0])
	}
	if event.Bearers[1].EBI != 7 || event.Bearers[1].PGWUserTEID != 0x22222222 || event.Bearers[1].QCI != 2 {
		t.Fatalf("bearer[1] = %+v", event.Bearers[1])
	}
	if event.EBI != 6 || event.PGWUserTEID != 0x11111111 {
		t.Fatalf("legacy first bearer fields = ebi %d teid %#x", event.EBI, event.PGWUserTEID)
	}
}

func TestDecodeIEsWithRawParsesEBIChildPayload(t *testing.T) {
	raw := []byte{0x49, 0x00, 0x01, 0x00, 0x05}
	ies, err := decodeIEsWithRaw(raw)
	if err != nil {
		t.Fatalf("decodeIEsWithRaw() error = %v", err)
	}
	if len(ies) != 1 {
		t.Fatalf("IE count = %d", len(ies))
	}
	if ies[0].Type != ieEBI || ies[0].Length != 1 || ies[0].Instance != 0 || ies[0].Offset != 0 || len(ies[0].Payload) != 1 || ies[0].Payload[0] != 0x05 {
		t.Fatalf("decoded IE = %+v payload=%x raw=%x", ies[0], ies[0].Payload, ies[0].Raw)
	}
	ebi, err := parseEBI(ies[0].Payload)
	if err != nil || ebi != 5 {
		t.Fatalf("parseEBI() = %d, %v", ebi, err)
	}
}

func TestDecodeIEsWithRawParsesEBIHighNibble(t *testing.T) {
	raw := []byte{0x49, 0x00, 0x01, 0x00, 0x85}
	ies, err := decodeIEsWithRaw(raw)
	if err != nil {
		t.Fatalf("decodeIEsWithRaw() error = %v", err)
	}
	ebi, err := parseEBI(ies[0].Payload)
	if err != nil || ebi != 5 {
		t.Fatalf("parseEBI() = %d, %v", ebi, err)
	}
}

func TestDecodeIEsWithRawDoesNotDecodeInstanceAsPayload(t *testing.T) {
	raw := []byte{0x49, 0x00, 0x01, 0x05, 0x06}
	ies, err := decodeIEsWithRaw(raw)
	if err != nil {
		t.Fatalf("decodeIEsWithRaw() error = %v", err)
	}
	if ies[0].Instance != 5 || len(ies[0].Payload) != 1 || ies[0].Payload[0] != 0x06 {
		t.Fatalf("decoded IE = %+v payload=%x", ies[0], ies[0].Payload)
	}
	ebi, err := parseEBI(ies[0].Payload)
	if err != nil || ebi != 6 {
		t.Fatalf("parseEBI() = %d, %v", ebi, err)
	}
}

func TestParseCreateBearerRequestRejectsInvalidGroupedEBIZero(t *testing.T) {
	req := message{
		Type:     msgCreateBearerReq,
		TEID:     0xdeadbeef,
		HasTEID:  true,
		Sequence: 101,
		Payload: encodeIEs(
			ie{Type: ieBearerContext, Payload: encodeIEs(
				ie{Type: ieEBI, Payload: []byte{0x00}},
				fteidIE(2, ifaceS2BPGWGTPU, 0x33333333, net.ParseIP("10.90.250.92")),
			)},
		),
	}
	event, err := parseCreateBearerRequest(req, &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30112})
	if err == nil {
		t.Fatal("parseCreateBearerRequest() error = nil")
	}
	if !strings.Contains(err.Error(), "missing EBI") {
		t.Fatalf("parseCreateBearerRequest() error = %v", err)
	}
	if len(event.BearerContexts) != 1 || event.BearerContexts[0].EBIRawIEHex != "4900010000" || event.BearerContexts[0].EBIPayloadHex != "00" {
		t.Fatalf("bearer contexts = %+v", event.BearerContexts)
	}
}

func TestParseCreateBearerRequestAcceptsUnassignedChildEBIWithLinkedDefault(t *testing.T) {
	req := message{
		Type:     msgCreateBearerReq,
		TEID:     0xdeadbeef,
		HasTEID:  true,
		Sequence: 102,
		Payload: encodeIEs(
			ebiValueIE(5),
			ie{Type: ieBearerContext, Payload: encodeIEs(
				ie{Type: ieEBI, Payload: []byte{0x00}},
				fteidIE(2, ifaceS2BPGWGTPU, 0x33333333, net.ParseIP("10.90.250.92")),
				ie{Type: ieTFT, Payload: []byte{0x21}},
				ie{Type: ieBearerQoS, Payload: []byte{0, 1}},
			)},
		),
	}
	event, err := parseCreateBearerRequest(req, &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30112})
	if err != nil {
		t.Fatalf("parseCreateBearerRequest() error = %v", err)
	}
	if event.LinkedDefaultEBI != 5 {
		t.Fatalf("LinkedDefaultEBI = %d", event.LinkedDefaultEBI)
	}
	if len(event.Bearers) != 1 || !event.Bearers[0].UnassignedEBI || event.Bearers[0].EBI != 0 || event.Bearers[0].PGWUserTEID != 0x33333333 {
		t.Fatalf("bearers = %+v", event.Bearers)
	}
}

func TestParseDeleteBearerRequestMasksEBI(t *testing.T) {
	req := message{
		Type:     msgDeleteBearerReq,
		TEID:     0xdeadbeef,
		HasTEID:  true,
		Sequence: 100,
		Payload: encodeIEs(ie{Type: ieBearerContext, Payload: encodeIEs(
			ie{Type: ieEBI, Payload: []byte{0xf5}},
		)}),
	}
	event, err := parseDeleteBearerRequest(req, &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30048})
	if err != nil {
		t.Fatalf("parseDeleteBearerRequest() error = %v", err)
	}
	if len(event.EBIs) != 1 || event.EBIs[0] != 5 {
		t.Fatalf("EBIs = %v", event.EBIs)
	}
}
