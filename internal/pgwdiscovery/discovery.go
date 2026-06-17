// Package pgwdiscovery resolves the PGW GTPv2-C control-plane address per 3GPP TS 29.303.
//
// Each UE attach triggers a per-APN lookup: DNS NAPTR → A record chain.
// Prefers x-3gpp-pgw:x-s2b-gtp service tags; optionally falls back to x-s5-gtp/x-s8-gtp.
// Falls back to the static pgw_gtpc config address when DNS is disabled or fails.
package pgwdiscovery

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Method identifies how the PGW GTPv2-C address was resolved.
type Method string

const (
	MethodStatic       Method = "static"
	MethodDNS_S2B      Method = "dns_s2b"
	MethodDNS_S5S8     Method = "dns_s5s8_fallback"
)

// Config holds PGW discovery parameters, populated from config.PGWDiscoveryConfig.
type Config struct {
	DNSEnabled        bool
	AllowS5S8Fallback bool
	StaticPGWC        string
	MCC               string
	MNC               string
}

// Discover returns the PGW GTPv2-C IPv4 for the given APN.
// When DNS is disabled or the NAPTR query yields no usable result, it falls back
// to cfg.StaticPGWC. The resolved address and method are logged at debug level.
func Discover(ctx context.Context, log *slog.Logger, cfg Config, apn string) net.IP {
	if !cfg.DNSEnabled {
		ip := net.ParseIP(cfg.StaticPGWC)
		log.Debug("PGW-C address resolved",
			"method", MethodStatic,
			"apn", apn,
			"pgw_gtpc", ip,
		)
		return ip
	}

	fqdn := apnFQDN(apn, cfg.MCC, cfg.MNC)
	ip, method, err := discoverViaDNS(ctx, cfg, fqdn)
	if err != nil || ip == nil {
		fallback := net.ParseIP(cfg.StaticPGWC)
		log.Warn("PGW-C DNS discovery failed, using static config",
			"apn", apn,
			"fqdn", fqdn,
			"error", err,
			"fallback_pgw_gtpc", fallback,
		)
		log.Debug("PGW-C address resolved",
			"method", MethodStatic,
			"apn", apn,
			"pgw_gtpc", fallback,
		)
		return fallback
	}

	log.Debug("PGW-C address resolved",
		"method", method,
		"apn", apn,
		"fqdn", fqdn,
		"pgw_gtpc", ip,
	)
	return ip
}

// apnFQDN constructs the APN FQDN per 3GPP TS 29.303 §5.
// Format: <APN-NI>.apn.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
func apnFQDN(apn, mcc, mnc string) string {
	return fmt.Sprintf("%s.apn.epc.mnc%s.mcc%s.3gppnetwork.org", apn, mnc, mcc)
}

type naptrRecord struct {
	Order       uint16
	Preference  uint16
	Flags       string // lower-cased, quote-stripped
	Service     string
	Replacement string // trailing dot removed
}

func discoverViaDNS(ctx context.Context, cfg Config, fqdn string) (net.IP, Method, error) {
	records, err := queryNAPTR(ctx, fqdn)
	if err != nil {
		return nil, "", err
	}

	// Sort by order then preference per RFC 2915 §2.
	sort.Slice(records, func(i, j int) bool {
		if records[i].Order != records[j].Order {
			return records[i].Order < records[j].Order
		}
		return records[i].Preference < records[j].Preference
	})

	// Prefer S2b-specific PGW records (TS 29.303 §5.2).
	for _, r := range records {
		if isS2BService(r.Service) {
			ip, err := resolveNAPTR(ctx, r)
			if err != nil {
				continue
			}
			return ip, MethodDNS_S2B, nil
		}
	}

	// Optional S5/S8 fallback (TS 29.303 §5.2, non-S2b interfaces).
	if cfg.AllowS5S8Fallback {
		for _, r := range records {
			if isS5S8Service(r.Service) {
				ip, err := resolveNAPTR(ctx, r)
				if err != nil {
					continue
				}
				return ip, MethodDNS_S5S8, nil
			}
		}
	}

	return nil, "", fmt.Errorf("no matching PGW NAPTR record for %s (s5s8_fallback=%v)", fqdn, cfg.AllowS5S8Fallback)
}

// isS2BService reports whether the NAPTR service tag indicates a PGW with S2b-GTP support.
// The service field may combine multiple interfaces: "x-3gpp-pgw:x-s2b-gtp:x-s5-gtp".
func isS2BService(svc string) bool {
	return strings.Contains(svc, "x-3gpp-pgw") && strings.Contains(svc, "x-s2b-gtp")
}

// isS5S8Service reports whether the NAPTR service tag indicates a PGW with S5/S8-GTP support.
func isS5S8Service(svc string) bool {
	return strings.Contains(svc, "x-3gpp-pgw") &&
		(strings.Contains(svc, "x-s5-gtp") || strings.Contains(svc, "x-s8-gtp"))
}

func queryNAPTR(ctx context.Context, fqdn string) ([]naptrRecord, error) {
	resolvConf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	if len(resolvConf.Servers) == 0 {
		return nil, fmt.Errorf("no nameservers in /etc/resolv.conf")
	}

	c := &dns.Client{
		ReadTimeout: 3 * time.Second,
		DialTimeout: 3 * time.Second,
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeNAPTR)
	m.RecursionDesired = true

	var resp *dns.Msg
	for _, server := range resolvConf.Servers {
		addr := net.JoinHostPort(server, resolvConf.Port)
		r, _, qErr := c.ExchangeContext(ctx, m, addr)
		if qErr != nil {
			continue
		}
		resp = r
		break
	}
	if resp == nil {
		return nil, fmt.Errorf("NAPTR query for %s failed on all nameservers", fqdn)
	}

	var records []naptrRecord
	for _, rr := range resp.Answer {
		naptr, ok := rr.(*dns.NAPTR)
		if !ok {
			continue
		}
		records = append(records, naptrRecord{
			Order:       naptr.Order,
			Preference:  naptr.Preference,
			Flags:       strings.ToLower(strings.Trim(naptr.Flags, `"`)),
			Service:     naptr.Service,
			Replacement: strings.TrimSuffix(naptr.Replacement, "."),
		})
	}
	return records, nil
}

// resolveNAPTR resolves the final IPv4 from a NAPTR record.
// Flag "a" → direct A record lookup.
// Flag "s" → SRV lookup → A record lookup on the first SRV target.
func resolveNAPTR(ctx context.Context, r naptrRecord) (net.IP, error) {
	switch r.Flags {
	case "a":
		ips, err := net.DefaultResolver.LookupHost(ctx, r.Replacement)
		if err != nil {
			return nil, fmt.Errorf("A lookup for %s: %w", r.Replacement, err)
		}
		for _, ipStr := range ips {
			if ip := net.ParseIP(ipStr).To4(); ip != nil {
				return ip, nil
			}
		}
		return nil, fmt.Errorf("no IPv4 address for %s", r.Replacement)

	case "s":
		_, addrs, err := net.LookupSRV("", "", r.Replacement)
		if err != nil {
			return nil, fmt.Errorf("SRV lookup for %s: %w", r.Replacement, err)
		}
		for _, addr := range addrs {
			target := strings.TrimSuffix(addr.Target, ".")
			ips, lErr := net.DefaultResolver.LookupHost(ctx, target)
			if lErr != nil {
				continue
			}
			for _, ipStr := range ips {
				if ip := net.ParseIP(ipStr).To4(); ip != nil {
					return ip, nil
				}
			}
		}
		return nil, fmt.Errorf("no IPv4 from SRV targets for %s", r.Replacement)

	default:
		return nil, fmt.Errorf("unsupported NAPTR flag %q for %s", r.Flags, r.Replacement)
	}
}
