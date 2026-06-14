package gtpu

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncodeParseTPDU(t *testing.T) {
	payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 150, 3, 189, 1, 1, 1, 1}
	encoded, err := encodeTPDU(2148884483, payload)
	if err != nil {
		t.Fatalf("encodeTPDU() error = %v", err)
	}
	if encoded[0] != gtpuVersionPT || encoded[1] != gtpuMsgTPDU {
		t.Fatalf("unexpected GTP-U header flags/type: %02x/%02x", encoded[0], encoded[1])
	}
	if got := binary.BigEndian.Uint16(encoded[2:4]); got != uint16(len(payload)) {
		t.Fatalf("length = %d", got)
	}
	parsed, err := parseGTPU(encoded)
	if err != nil {
		t.Fatalf("parseGTPU() error = %v", err)
	}
	if parsed.TEID != 2148884483 {
		t.Fatalf("TEID = %d", parsed.TEID)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestParseTPDUSkipsOptionalHeader(t *testing.T) {
	payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 150, 3, 189, 1, 1, 1, 1}
	packet := make([]byte, 12+len(payload))
	packet[0] = gtpuVersionPT | gtpuFlagS
	packet[1] = gtpuMsgTPDU
	binary.BigEndian.PutUint16(packet[2:4], uint16(4+len(payload)))
	binary.BigEndian.PutUint32(packet[4:8], 1631877775)
	binary.BigEndian.PutUint16(packet[8:10], 7)
	copy(packet[12:], payload)
	parsed, err := parseGTPU(packet)
	if err != nil {
		t.Fatalf("parseGTPU() error = %v", err)
	}
	if parsed.Sequence != 7 {
		t.Fatalf("sequence = %d", parsed.Sequence)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestSourceIPv4(t *testing.T) {
	payload := []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 10, 150, 3, 189, 1, 1, 1, 1}
	if got := sourceIP(payload).String(); got != "10.150.3.189" {
		t.Fatalf("sourceIP() = %s", got)
	}
}
