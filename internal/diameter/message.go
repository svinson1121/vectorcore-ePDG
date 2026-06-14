package diameter

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	FlagRequest   byte = 0x80
	FlagProxiable byte = 0x40
	FlagVendorAVP byte = 0x80
	FlagMandatory byte = 0x40

	Version   byte = 1
	HeaderLen      = 20

	CommandCER uint32 = 257
	CommandDER uint32 = 268
	CommandDWR uint32 = 280
	CommandDPR uint32 = 282
	CommandSTR uint32 = 275
)

const (
	AVPUserName                    uint32 = 1
	AVPHostIPAddress               uint32 = 257
	AVPAuthApplicationID           uint32 = 258
	AVPVendorSpecificApplicationID uint32 = 260
	AVPSessionID                   uint32 = 263
	AVPOriginHost                  uint32 = 264
	AVPSupportedVendorID           uint32 = 265
	AVPVendorID                    uint32 = 266
	AVPFirmwareRevision            uint32 = 267
	AVPResultCode                  uint32 = 268
	AVPProductName                 uint32 = 269
	AVPAuthRequestType             uint32 = 274
	AVPTerminationCause            uint32 = 295
	AVPOriginStateID               uint32 = 278
	AVPDestinationRealm            uint32 = 283
	AVPDestinationHost             uint32 = 293
	AVPOriginRealm                 uint32 = 296
	AVPExperimentalResult          uint32 = 297
	AVPExperimentalResultCode      uint32 = 298
	AVPInbandSecurityID            uint32 = 299
	AVPEAPPayload                  uint32 = 462
	AVPEAPMasterSessionKey         uint32 = 464
	AVPServiceSelection            uint32 = 493
	AVPAPNConfiguration            uint32 = 1430
	AVPAMBR                        uint32 = 1435
	AVPNon3GPPUserData             uint32 = 1500
	AVPMaxRequestedBandwidthUL     uint32 = 516
	AVPMaxRequestedBandwidthDL     uint32 = 515
)

const (
	Vendor3GPP     uint32 = 10415
	VendorETSI     uint32 = 13019
	InbandNoSec    uint32 = 0
	FirmwareRevOne uint32 = 1
)

type Message struct {
	Flags       byte
	CommandCode uint32
	AppID       uint32
	HopByHop    uint32
	EndToEnd    uint32
	AVPs        []AVP
}

type AVP struct {
	Code     uint32
	VendorID uint32
	Flags    byte
	Data     []byte
}

func (m Message) IsRequest() bool {
	return m.Flags&FlagRequest != 0
}

func (m Message) Encode() []byte {
	var payload []byte
	for _, a := range m.AVPs {
		payload = append(payload, a.Encode()...)
	}
	totalLen := HeaderLen + len(payload)
	out := make([]byte, totalLen)
	out[0] = Version
	put24(out[1:4], uint32(totalLen))
	out[4] = m.Flags
	put24(out[5:8], m.CommandCode)
	binary.BigEndian.PutUint32(out[8:12], m.AppID)
	binary.BigEndian.PutUint32(out[12:16], m.HopByHop)
	binary.BigEndian.PutUint32(out[16:20], m.EndToEnd)
	copy(out[HeaderLen:], payload)
	return out
}

func DecodeMessage(r io.Reader) (Message, error) {
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return Message{}, err
	}
	if prefix[0] != Version {
		return Message{}, fmt.Errorf("unsupported Diameter version %d", prefix[0])
	}
	length := int(read24(prefix[1:4]))
	if length < HeaderLen {
		return Message{}, fmt.Errorf("Diameter message length %d too short", length)
	}
	rest := make([]byte, length-4)
	if _, err := io.ReadFull(r, rest); err != nil {
		return Message{}, err
	}
	full := append(prefix, rest...)
	msg := Message{
		Flags:       full[4],
		CommandCode: read24(full[5:8]),
		AppID:       binary.BigEndian.Uint32(full[8:12]),
		HopByHop:    binary.BigEndian.Uint32(full[12:16]),
		EndToEnd:    binary.BigEndian.Uint32(full[16:20]),
	}
	avps, err := DecodeAVPs(full[HeaderLen:])
	if err != nil {
		return Message{}, err
	}
	msg.AVPs = avps
	return msg, nil
}

func (a AVP) Encode() []byte {
	flags := a.Flags
	headerSize := 8
	if a.VendorID != 0 {
		flags |= FlagVendorAVP
		headerSize = 12
	}
	length := headerSize + len(a.Data)
	padded := Pad4(length)
	out := make([]byte, padded)
	binary.BigEndian.PutUint32(out[0:4], a.Code)
	out[4] = flags
	put24(out[5:8], uint32(length))
	offset := 8
	if a.VendorID != 0 {
		binary.BigEndian.PutUint32(out[8:12], a.VendorID)
		offset = 12
	}
	copy(out[offset:], a.Data)
	return out
}

func DecodeAVPs(data []byte) ([]AVP, error) {
	var out []AVP
	for len(data) > 0 {
		if len(data) < 8 {
			return nil, fmt.Errorf("AVP header truncated")
		}
		code := binary.BigEndian.Uint32(data[0:4])
		flags := data[4]
		length := int(read24(data[5:8]))
		headerSize := 8
		var vendorID uint32
		if flags&FlagVendorAVP != 0 {
			headerSize = 12
			if len(data) < headerSize {
				return nil, fmt.Errorf("vendor AVP header truncated")
			}
			vendorID = binary.BigEndian.Uint32(data[8:12])
		}
		if length < headerSize || len(data) < length {
			return nil, fmt.Errorf("AVP length invalid")
		}
		payload := append([]byte(nil), data[headerSize:length]...)
		out = append(out, AVP{Code: code, VendorID: vendorID, Flags: flags, Data: payload})
		step := Pad4(length)
		if len(data) < step {
			return nil, fmt.Errorf("AVP padding truncated")
		}
		data = data[step:]
	}
	return out, nil
}

func UTF8AVP(code, vendor uint32, value string) AVP {
	return UTF8AVPFlags(code, vendor, FlagMandatory, value)
}

func UTF8AVPFlags(code, vendor uint32, flags byte, value string) AVP {
	return AVP{Code: code, VendorID: vendor, Flags: flags, Data: []byte(value)}
}

func OctetAVP(code, vendor uint32, flags byte, value []byte) AVP {
	return AVP{Code: code, VendorID: vendor, Flags: flags, Data: append([]byte(nil), value...)}
}

func Uint32AVP(code, vendor, value uint32) AVP {
	return Uint32AVPFlags(code, vendor, FlagMandatory, value)
}

func Uint32AVPFlags(code, vendor uint32, flags byte, value uint32) AVP {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return AVP{Code: code, VendorID: vendor, Flags: flags, Data: data}
}

func GroupedAVP(code, vendor uint32, children ...AVP) AVP {
	var data []byte
	for _, child := range children {
		data = append(data, child.Encode()...)
	}
	return AVP{Code: code, VendorID: vendor, Flags: FlagMandatory, Data: data}
}

func AddressAVP(code uint32, ip4 [4]byte) AVP {
	data := []byte{0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3]}
	return AVP{Code: code, Flags: FlagMandatory, Data: data}
}

func FindAVP(avps []AVP, code, vendor uint32) (AVP, bool) {
	for _, a := range avps {
		if a.Code == code && a.VendorID == vendor {
			return a, true
		}
	}
	return AVP{}, false
}

func AVPString(avps []AVP, code, vendor uint32) string {
	if a, ok := FindAVP(avps, code, vendor); ok {
		return string(a.Data)
	}
	return ""
}

func AVPUint32(avps []AVP, code, vendor uint32) (uint32, bool) {
	a, ok := FindAVP(avps, code, vendor)
	if !ok || len(a.Data) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(a.Data[:4]), true
}

func ExperimentalResultCode(avps []AVP) (uint32, bool) {
	a, ok := FindAVP(avps, AVPExperimentalResult, 0)
	if !ok {
		return 0, false
	}
	children, err := DecodeAVPs(a.Data)
	if err != nil {
		return 0, false
	}
	return AVPUint32(children, AVPExperimentalResultCode, 0)
}

func put24(dst []byte, value uint32) {
	dst[0] = byte(value >> 16)
	dst[1] = byte(value >> 8)
	dst[2] = byte(value)
}

func read24(src []byte) uint32 {
	return uint32(src[0])<<16 | uint32(src[1])<<8 | uint32(src[2])
}

func Pad4(n int) int {
	if rem := n % 4; rem != 0 {
		return n + 4 - rem
	}
	return n
}
