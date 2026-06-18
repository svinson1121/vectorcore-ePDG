package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const (
	DefaultPath      = "/opt/vectorcore/etc/epdg.yaml"
	SWMVendorID      = 10415
	SWMApplicationID = 16777264
	GTPUPort         = 2152
)

type Config struct {
	EPDG         EPDGConfig
	Logging      LoggingConfig
	IKEv2        IKEv2Config
	SWM          SWMConfig
	GTP          GTPConfig
	APN          APNConfig
	PCO          PCOConfig
	Shutdown     ShutdownConfig
	PGWDiscovery PGWDiscoveryConfig
}

type PGWDiscoveryConfig struct {
	// DNSEnabled enables per-attach DNS PGW discovery per 3GPP TS 29.303.
	// When false (default), pgw_gtpc is used directly.
	DNSEnabled bool
	// AllowS5S8Fallback allows falling back to x-s5-gtp/x-s8-gtp NAPTR records
	// when no x-s2b-gtp record is present in DNS.
	AllowS5S8Fallback bool
}

type IKEv2Config struct {
	// ListenAddr is the IP to bind IKEv2 listeners on port 500 and 4500.
	// Default "0.0.0.0" listens on all interfaces.
	ListenAddr string
	// ListenAddrV6 is the IPv6 address to additionally bind IKEv2 listeners on.
	// Empty (default) disables IPv6 — only ListenAddr (IPv4) is bound. Set to
	// "::" or a specific IPv6 address to enable dual-stack listening.
	ListenAddrV6 string
	// ListenIfname optionally restricts listening to a named interface.
	ListenIfname string
	// CertFile is the path to the ePDG X.509 certificate (PEM).
	CertFile string
	// KeyFile is the path to the ePDG private key (PEM).
	KeyFile string
	// CAFile is the path to the CA certificate for UE cert validation (PEM).
	CAFile string
	// DPDEnabled controls whether Dead Peer Detection is active. Default true.
	DPDEnabled bool
	// DPDDelay is the idle time in seconds before sending a DPD probe. Default 30.
	DPDDelay int
	// DPDTimeout is the seconds to wait for a DPD response before tearing down. Default 120.
	DPDTimeout int
}

type EPDGConfig struct {
	Name      string
	Realm     string
	MCC       string
	MNC       string
	MNCLength int
}

type LoggingConfig struct {
	Level string
	File  string
}

type SWMConfig struct {
	LocalAddr               string
	PeerAddr                string
	PeerPort                int
	Proto                   string
	OriginHost              string
	OriginRealm             string
	DestinationHost         string
	DestinationRealm        string
	WatchdogIntervalSeconds int
	WatchdogTimeoutSeconds  int
}

type GTPConfig struct {
	LocalGTPC                 string
	LocalGTPU                 string
	LocalPort                 int
	PGWGTPC                   string
	TunAddr                   string
	MTU                       int
	ValidateOuterPeer         bool
	StrictPeerCheck           bool
	DedicatedBearers          DedicatedBearerConfig
	BPF                       BPFConfig
	// MaxSequence caps the GTPv2-C sequence number range. Default 0 means
	// use the full 24-bit range (0xFFFFFF) per TS 29.274 §6.1.2.
	// Set to 8388607 (0x7FFFFF) for Cisco StarOS qvpc-si interop — StarOS
	// incorrectly rejects sequences with the 23rd bit set.
	MaxSequence uint32
}

type DedicatedBearerConfig struct {
	Enabled            bool
	TFTUplinkSelection bool
}

type BPFConfig struct {
	XDPAttachMode string // "generic" | "native" | "offload"
	XDPInterface  string // NIC receiving UDP/2152 from PGW; auto-derived if empty
	MapMaxEntries int    // max BPF map entries; default 4096
}

type APNConfig struct {
	Default string
}

type PCOConfig struct {
	Enabled        bool
	RequestDNSv4   bool
	RequestDNSv6   bool
	RequestPCSCFv4 bool
	RequestPCSCFv6 bool
	IncludeAPCO    bool
	StrictDecode   bool
}

type ShutdownConfig struct {
	TimeoutSeconds int
}

func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := Default()
	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := stripComment(scanner.Text())
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			section = strings.TrimSuffix(strings.TrimSpace(line), ":")
			continue
		}
		key, value, ok := parseKeyValue(line)
		if !ok {
			return nil, fmt.Errorf("invalid config line: %q", scanner.Text())
		}
		if err := setValue(cfg, section, key, value); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func stripComment(line string) string {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		return line[:idx]
	}
	return line
}

func parseKeyValue(line string) (string, string, bool) {
	parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
	return key, value, key != ""
}

func setValue(cfg *Config, section, key, value string) error {
	switch section {
	case "epdg":
		switch key {
		case "name":
			cfg.EPDG.Name = value
		case "realm":
			cfg.EPDG.Realm = value
		case "mcc":
			cfg.EPDG.MCC = value
		case "mnc":
			cfg.EPDG.MNC = value
		case "mnc_length":
			return setInt(value, &cfg.EPDG.MNCLength, section, key)
		}
	case "ikev2":
		switch key {
		case "listen_addr":
			cfg.IKEv2.ListenAddr = value
		case "listen_addr_v6":
			cfg.IKEv2.ListenAddrV6 = value
		case "listen_ifname":
			cfg.IKEv2.ListenIfname = value
		case "cert_file":
			cfg.IKEv2.CertFile = value
		case "key_file":
			cfg.IKEv2.KeyFile = value
		case "ca_file":
			cfg.IKEv2.CAFile = value
		case "dpd_enabled":
			return setBool(value, &cfg.IKEv2.DPDEnabled, section, key)
		case "dpd_delay":
			return setInt(value, &cfg.IKEv2.DPDDelay, section, key)
		case "dpd_timeout":
			return setInt(value, &cfg.IKEv2.DPDTimeout, section, key)
		}
	case "logging":
		switch key {
		case "level":
			cfg.Logging.Level = value
		case "file":
			cfg.Logging.File = value
		}
	case "swm":
		switch key {
		case "local_addr":
			cfg.SWM.LocalAddr = value
		case "peer_addr":
			cfg.SWM.PeerAddr = value
		case "peer_port":
			return setInt(value, &cfg.SWM.PeerPort, section, key)
		case "proto":
			cfg.SWM.Proto = value
		case "origin_host":
			cfg.SWM.OriginHost = value
		case "origin_realm":
			cfg.SWM.OriginRealm = value
		case "destination_host":
			cfg.SWM.DestinationHost = value
		case "destination_realm":
			cfg.SWM.DestinationRealm = value
		case "watchdog_interval_seconds":
			return setInt(value, &cfg.SWM.WatchdogIntervalSeconds, section, key)
		case "watchdog_timeout_seconds":
			return setInt(value, &cfg.SWM.WatchdogTimeoutSeconds, section, key)
		}
	case "gtp":
		switch key {
		case "local_gtpc":
			cfg.GTP.LocalGTPC = value
		case "local_gtpu":
			cfg.GTP.LocalGTPU = value
		case "local_port":
			return setInt(value, &cfg.GTP.LocalPort, section, key)
		case "pgw_gtpc":
			cfg.GTP.PGWGTPC = value
		case "tun_addr":
			cfg.GTP.TunAddr = value
		case "mtu":
			return setInt(value, &cfg.GTP.MTU, section, key)
		case "validate_outer_peer":
			return setBool(value, &cfg.GTP.ValidateOuterPeer, section, key)
		case "strict_peer_check":
			return setBool(value, &cfg.GTP.StrictPeerCheck, section, key)
		case "max_sequence":
			return setUint32(value, &cfg.GTP.MaxSequence, section, key)
		}
	case "dedicated_bearers":
		switch key {
		case "enabled":
			return setBool(value, &cfg.GTP.DedicatedBearers.Enabled, section, key)
		case "tft_uplink_selection":
			return setBool(value, &cfg.GTP.DedicatedBearers.TFTUplinkSelection, section, key)
		}
	case "apn":
		switch key {
		case "default":
			cfg.APN.Default = value
		}
	case "pco":
		switch key {
		case "enabled":
			return setBool(value, &cfg.PCO.Enabled, section, key)
		case "request_dns_v4":
			return setBool(value, &cfg.PCO.RequestDNSv4, section, key)
		case "request_dns_v6":
			return setBool(value, &cfg.PCO.RequestDNSv6, section, key)
		case "request_pcscf_v4":
			return setBool(value, &cfg.PCO.RequestPCSCFv4, section, key)
		case "request_pcscf_v6":
			return setBool(value, &cfg.PCO.RequestPCSCFv6, section, key)
		case "include_apco":
			return setBool(value, &cfg.PCO.IncludeAPCO, section, key)
		case "strict_decode":
			return setBool(value, &cfg.PCO.StrictDecode, section, key)
		}
	case "bpf":
		switch key {
		case "xdp_attach_mode":
			cfg.GTP.BPF.XDPAttachMode = value
		case "xdp_interface":
			cfg.GTP.BPF.XDPInterface = value
		case "map_max_entries":
			return setInt(value, &cfg.GTP.BPF.MapMaxEntries, section, key)
		}
	case "shutdown":
		switch key {
		case "timeout_seconds":
			return setInt(value, &cfg.Shutdown.TimeoutSeconds, section, key)
		}
	case "pgw_discovery":
		switch key {
		case "dns_enabled":
			return setBool(value, &cfg.PGWDiscovery.DNSEnabled, section, key)
		case "allow_s5s8_fallback":
			return setBool(value, &cfg.PGWDiscovery.AllowS5S8Fallback, section, key)
		}
	default:
		return fmt.Errorf("unknown config section %q", section)
	}
	return nil
}

func Default() *Config {
	return &Config{
		Logging: LoggingConfig{
			Level: "info",
			File:  "/var/log/vectorcore/epdg/epdg.log",
		},
		IKEv2: IKEv2Config{
			ListenAddr: "0.0.0.0",
			DPDEnabled: true,
			DPDDelay:   30,
			DPDTimeout: 120,
		},
		SWM: SWMConfig{
			Proto:                   "sctp",
			WatchdogIntervalSeconds: 30,
			WatchdogTimeoutSeconds:  10,
		},
		GTP: GTPConfig{
			LocalPort:         GTPUPort,
			MTU:               1400,
			ValidateOuterPeer: true,
			StrictPeerCheck:   true,
			DedicatedBearers: DedicatedBearerConfig{
				Enabled:            true,
				TFTUplinkSelection: true,
			},
			BPF: BPFConfig{
				XDPAttachMode: "generic",
				MapMaxEntries: 4096,
			},
		},
		PCO: PCOConfig{
			Enabled: true,
		},
		Shutdown: ShutdownConfig{
			TimeoutSeconds: 5,
		},
	}
}

func setInt(value string, dst *int, section, key string) error {
	n, err := strconv.Atoi(value)
	if err != nil {
		return fmt.Errorf("%s.%s must be an integer: %w", section, key, err)
	}
	*dst = n
	return nil
}

func setUint32(value string, dst *uint32, section, key string) error {
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return fmt.Errorf("%s.%s must be a non-negative integer: %w", section, key, err)
	}
	*dst = uint32(n)
	return nil
}

func setBool(value string, dst *bool, section, key string) error {
	b, err := strconv.ParseBool(value)
	if err != nil {
		return fmt.Errorf("%s.%s must be a boolean: %w", section, key, err)
	}
	*dst = b
	return nil
}
