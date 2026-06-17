package pco

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// 3GPP TS 24.008 table 10.5.154 defines these PCO container IDs.
const (
	ContainerPCSCFIPv6 uint16 = 0x0001
	ContainerDNSIPv6   uint16 = 0x0003
	ContainerPCSCFIPv4 uint16 = 0x000c
	ContainerDNSIPv4   uint16 = 0x000d
)

type Container struct {
	ProtocolID uint16
	Contents   []byte
}

type PCO struct {
	Extension  bool
	Containers []Container
}

type Decoded struct {
	PCO         *PCO
	DNSv4       []net.IP
	DNSv6       []net.IP
	PCSCFv4     []net.IP
	PCSCFv6     []net.IP
	Unsupported []Container
}

func Decode(payload []byte, strict bool) (*Decoded, error) {
	if len(payload) == 0 {
		return nil, nil
	}
	out := &Decoded{
		PCO: &PCO{Extension: payload[0]&0x80 != 0},
	}
	rest := payload[1:]
	for len(rest) > 0 {
		if len(rest) < 3 {
			if strict {
				return nil, fmt.Errorf("PCO container header truncated")
			}
			out.Unsupported = append(out.Unsupported, Container{Contents: append([]byte(nil), rest...)})
			break
		}
		id := binary.BigEndian.Uint16(rest[0:2])
		l := int(rest[2])
		if len(rest) < 3+l {
			if strict {
				return nil, fmt.Errorf("PCO container 0x%04x length %d exceeds remaining %d", id, l, len(rest)-3)
			}
			out.Unsupported = append(out.Unsupported, Container{ProtocolID: id, Contents: append([]byte(nil), rest[3:]...)})
			break
		}
		c := Container{ProtocolID: id, Contents: append([]byte(nil), rest[3:3+l]...)}
		out.PCO.Containers = append(out.PCO.Containers, c)
		out.decodeKnown(c, strict)
		rest = rest[3+l:]
	}
	if strict && len(out.Unsupported) > 0 {
		return nil, fmt.Errorf("PCO contains %d unsupported or malformed containers", len(out.Unsupported))
	}
	return out, nil
}

func Encode(p PCO) ([]byte, error) {
	first := byte(0)
	if p.Extension {
		first = 0x80
	}
	out := []byte{first}
	for _, c := range p.Containers {
		if len(c.Contents) > 255 {
			return nil, fmt.Errorf("PCO container 0x%04x too large: %d", c.ProtocolID, len(c.Contents))
		}
		var hdr [3]byte
		binary.BigEndian.PutUint16(hdr[0:2], c.ProtocolID)
		hdr[2] = byte(len(c.Contents))
		out = append(out, hdr[:]...)
		out = append(out, c.Contents...)
	}
	return out, nil
}

func Request(dnsV4, dnsV6, pcscfV4, pcscfV6 bool) PCO {
	var containers []Container
	if pcscfV6 {
		containers = append(containers, Container{ProtocolID: ContainerPCSCFIPv6})
	}
	if pcscfV4 {
		containers = append(containers, Container{ProtocolID: ContainerPCSCFIPv4})
	}
	if dnsV6 {
		containers = append(containers, Container{ProtocolID: ContainerDNSIPv6})
	}
	if dnsV4 {
		containers = append(containers, Container{ProtocolID: ContainerDNSIPv4})
	}
	return PCO{Extension: true, Containers: containers}
}

func ProtocolIDs(containers []Container) []string {
	ids := make([]string, 0, len(containers))
	for _, c := range containers {
		ids = append(ids, fmt.Sprintf("0x%04x", c.ProtocolID))
	}
	return ids
}

func IPStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func JoinIPs(ips []net.IP) string {
	return strings.Join(IPStrings(ips), ",")
}

func (d *Decoded) decodeKnown(c Container, strict bool) {
	switch c.ProtocolID {
	case ContainerDNSIPv4:
		if len(c.Contents)%net.IPv4len != 0 {
			d.Unsupported = append(d.Unsupported, c)
		}
		d.DNSv4 = appendIPv4(d.DNSv4, c.Contents)
	case ContainerPCSCFIPv4:
		if len(c.Contents)%net.IPv4len != 0 {
			d.Unsupported = append(d.Unsupported, c)
		}
		d.PCSCFv4 = appendIPv4(d.PCSCFv4, c.Contents)
	case ContainerDNSIPv6:
		if len(c.Contents)%net.IPv6len != 0 {
			d.Unsupported = append(d.Unsupported, c)
		}
		d.DNSv6 = appendIPv6(d.DNSv6, c.Contents)
	case ContainerPCSCFIPv6:
		if len(c.Contents)%net.IPv6len != 0 {
			d.Unsupported = append(d.Unsupported, c)
		}
		d.PCSCFv6 = appendIPv6(d.PCSCFv6, c.Contents)
	default:
		d.Unsupported = append(d.Unsupported, c)
	}
}

func appendIPv4(dst []net.IP, b []byte) []net.IP {
	for len(b) >= net.IPv4len {
		dst = append(dst, net.IPv4(b[0], b[1], b[2], b[3]))
		b = b[net.IPv4len:]
	}
	return dst
}

func appendIPv6(dst []net.IP, b []byte) []net.IP {
	for len(b) >= net.IPv6len {
		dst = append(dst, append(net.IP(nil), b[:net.IPv6len]...))
		b = b[net.IPv6len:]
	}
	return dst
}
