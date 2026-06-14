package config

import (
	"bufio"
	"fmt"
	"log/slog"
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
	EPDG     EPDGConfig
	Logging  LoggingConfig
	IPC      IPCConfig
	IKEv2    IKEv2Config
	SWM      SWMConfig
	GTP      GTPConfig
	APN      APNConfig
	PCO      PCOConfig
	Datapath DatapathConfig
	Reauth   ReauthConfig
	Shutdown ShutdownConfig
}

type IKEv2Config struct {
	// ListenAddr is the IP to bind IKEv2 listeners on port 500 and 4500.
	// Default "0.0.0.0" listens on all interfaces.
	ListenAddr string
	// ListenIfname optionally restricts listening to a named interface.
	ListenIfname string
	// CertFile is the path to the ePDG X.509 certificate (PEM).
	CertFile string
	// KeyFile is the path to the ePDG private key (PEM).
	KeyFile string
	// CAFile is the path to the CA certificate for UE cert validation (PEM).
	CAFile string
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

type IPCConfig struct {
	// EPDGRequestSocket is owned by ePDG; the strongSwan plugin connects here
	// for auth and plugin-to-ePDG lifecycle messages.
	EPDGRequestSocket string
	// PluginControlSocket is owned by the strongSwan plugin; ePDG connects here
	// for forced disconnect commands caused by PGW/ePDG-side teardown.
	PluginControlSocket string

	// Deprecated compatibility fields. Use EPDGRequestSocket and
	// PluginControlSocket internally after ResolveLegacyAliases runs.
	Listen        string
	PluginControl string
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
	PGWGTPU                   string
	Recovery                  int
	TunName                   string
	TunAddr                   string
	MTU                       int
	ValidateOuterPeer         bool
	StrictPeerCheck           bool
	CleanupStaleRoutesOnStart bool
	UplinkCapture             UplinkCaptureConfig
	DedicatedBearers          DedicatedBearerConfig
	// MaxSequence caps the GTPv2-C sequence number range. Default 0 means
	// use the full 24-bit range (0xFFFFFF) per TS 29.274 §6.1.2.
	// Set to 8388607 (0x7FFFFF) for Cisco StarOS qvpc-si interop — StarOS
	// incorrectly rejects sequences with the 23rd bit set.
	MaxSequence uint32
}

type UplinkCaptureConfig struct {
	Mode                     string
	QueueNum                 int
	InstallRules             bool
	FirewallBackend          string
	ChainName                string
	IngressIfName            string
	QueueBypass              bool
	FailClosed               bool
	CleanupStaleRulesOnStart bool
}

type DedicatedBearerConfig struct {
	Enabled            bool
	TFTUplinkSelection bool
}

type APNConfig struct {
	Default string
}

type PCOConfig struct {
	Enabled      bool
	RequestDNS   bool
	RequestPCSCF bool
	RequestMTU   bool
	IncludeAPCO  bool
	StrictDecode bool
}

type DatapathConfig struct {
	EnableIPForwardingCheck    bool
	InstallRoutes              bool
	RequirePAAIPsecAlign       bool
	UplinkPolicyRoutingEnabled bool
	UplinkTableID              int
	UplinkTableName            string
	UplinkPriorityBase         int
}

type ReauthConfig struct {
	Mode                   string
	AllowFallbackNewAttach bool
	OnFailure              string
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
	cfg.ResolveLegacyAliases()
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
	case "ipc":
		switch key {
		case "epdg_request_socket":
			cfg.IPC.EPDGRequestSocket = value
		case "plugin_control_socket":
			cfg.IPC.PluginControlSocket = value
		case "listen":
			cfg.IPC.Listen = value
		case "plugin_control":
			cfg.IPC.PluginControl = value
		}
	case "ikev2":
		switch key {
		case "listen_addr":
			cfg.IKEv2.ListenAddr = value
		case "listen_ifname":
			cfg.IKEv2.ListenIfname = value
		case "cert_file":
			cfg.IKEv2.CertFile = value
		case "key_file":
			cfg.IKEv2.KeyFile = value
		case "ca_file":
			cfg.IKEv2.CAFile = value
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
		case "local_addr":
			cfg.GTP.LocalGTPU = value
		case "local_port":
			return setInt(value, &cfg.GTP.LocalPort, section, key)
		case "pgw_gtpc":
			cfg.GTP.PGWGTPC = value
		case "pgw_gtpu":
			cfg.GTP.PGWGTPU = value
		case "recovery":
			return setInt(value, &cfg.GTP.Recovery, section, key)
		case "tun_name":
			cfg.GTP.TunName = value
		case "tun_addr":
			cfg.GTP.TunAddr = value
		case "mtu":
			return setInt(value, &cfg.GTP.MTU, section, key)
		case "route_table":
			return setInt(value, &cfg.Datapath.UplinkTableID, section, key)
		case "validate_outer_peer":
			return setBool(value, &cfg.GTP.ValidateOuterPeer, section, key)
		case "strict_peer_check":
			return setBool(value, &cfg.GTP.StrictPeerCheck, section, key)
		case "cleanup_stale_routes_on_start":
			return setBool(value, &cfg.GTP.CleanupStaleRoutesOnStart, section, key)
		case "max_sequence":
			return setUint32(value, &cfg.GTP.MaxSequence, section, key)
		case "uplink_capture_mode":
			cfg.GTP.UplinkCapture.Mode = value
		case "nfqueue_queue_num":
			return setInt(value, &cfg.GTP.UplinkCapture.QueueNum, section, key)
		case "nfqueue_install_rules":
			return setBool(value, &cfg.GTP.UplinkCapture.InstallRules, section, key)
		case "nfqueue_firewall_backend":
			cfg.GTP.UplinkCapture.FirewallBackend = value
		case "nfqueue_chain_name":
			cfg.GTP.UplinkCapture.ChainName = value
		case "nfqueue_ingress_ifname":
			cfg.GTP.UplinkCapture.IngressIfName = value
		case "nfqueue_queue_bypass":
			return setBool(value, &cfg.GTP.UplinkCapture.QueueBypass, section, key)
		case "nfqueue_fail_closed":
			return setBool(value, &cfg.GTP.UplinkCapture.FailClosed, section, key)
		case "nfqueue_cleanup_stale_rules_on_start":
			return setBool(value, &cfg.GTP.UplinkCapture.CleanupStaleRulesOnStart, section, key)
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
		case "request_dns":
			return setBool(value, &cfg.PCO.RequestDNS, section, key)
		case "request_pcscf":
			return setBool(value, &cfg.PCO.RequestPCSCF, section, key)
		case "request_mtu":
			return setBool(value, &cfg.PCO.RequestMTU, section, key)
		case "include_apco":
			return setBool(value, &cfg.PCO.IncludeAPCO, section, key)
		case "strict_decode":
			return setBool(value, &cfg.PCO.StrictDecode, section, key)
		}
	case "datapath":
		switch key {
		case "enable_ip_forwarding_check":
			return setBool(value, &cfg.Datapath.EnableIPForwardingCheck, section, key)
		case "install_routes":
			return setBool(value, &cfg.Datapath.InstallRoutes, section, key)
		case "require_paa_ipsec_alignment":
			return setBool(value, &cfg.Datapath.RequirePAAIPsecAlign, section, key)
		case "uplink_policy_routing_enabled":
			return setBool(value, &cfg.Datapath.UplinkPolicyRoutingEnabled, section, key)
		case "uplink_table_id":
			return setInt(value, &cfg.Datapath.UplinkTableID, section, key)
		case "uplink_table_name":
			cfg.Datapath.UplinkTableName = value
		case "uplink_priority_base":
			return setInt(value, &cfg.Datapath.UplinkPriorityBase, section, key)
		}
	case "reauth":
		switch key {
		case "mode":
			cfg.Reauth.Mode = value
		case "allow_fallback_new_attach":
			return setBool(value, &cfg.Reauth.AllowFallbackNewAttach, section, key)
		case "on_failure":
			cfg.Reauth.OnFailure = value
		}
	case "shutdown":
		switch key {
		case "timeout_seconds":
			return setInt(value, &cfg.Shutdown.TimeoutSeconds, section, key)
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
		IPC: IPCConfig{
			EPDGRequestSocket:   "/run/vectorcore/epdg-eap.sock",
			PluginControlSocket: "/run/vectorcore/strongswan-eap.sock",
		},
		IKEv2: IKEv2Config{
			ListenAddr: "0.0.0.0",
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
			TunName:           "vc-gtpu0",
			MTU:               1400,
			ValidateOuterPeer: true,
			StrictPeerCheck:   true,
			UplinkCapture: UplinkCaptureConfig{
				Mode:            "nfqueue",
				QueueNum:        4200,
				InstallRules:    true,
				FirewallBackend: "iptables",
				ChainName:       "VECTORCORE-EPDG-UPLINK",
				FailClosed:      true,
			},
			DedicatedBearers: DedicatedBearerConfig{
				Enabled:            true,
				TFTUplinkSelection: false,
			},
		},
		PCO: PCOConfig{
			Enabled: true,
		},
		Datapath: DatapathConfig{
			UplinkPolicyRoutingEnabled: false,
			UplinkTableID:              4200,
			UplinkTableName:            "vectorcore-epdg-gtp",
			UplinkPriorityBase:         10000,
		},
		Reauth: ReauthConfig{
			Mode:                   "preserve_existing_s2b",
			AllowFallbackNewAttach: false,
			OnFailure:              "keep_existing_until_ipsec_delete",
		},
		Shutdown: ShutdownConfig{
			TimeoutSeconds: 5,
		},
	}
}

func (c *Config) ResolveLegacyAliases() {
	if c.IPC.EPDGRequestSocket == "" {
		c.IPC.EPDGRequestSocket = c.IPC.Listen
	}
	if c.IPC.PluginControlSocket == "" {
		c.IPC.PluginControlSocket = c.IPC.PluginControl
	}
}

func (c *Config) LogDeprecatedAliases(log *slog.Logger) {
	if log == nil {
		return
	}
	logIPCDeprecatedAlias(log, "ipc.listen", "ipc.epdg_request_socket", c.IPC.Listen, c.IPC.EPDGRequestSocket)
	logIPCDeprecatedAlias(log, "ipc.plugin_control", "ipc.plugin_control_socket", c.IPC.PluginControl, c.IPC.PluginControlSocket)
}

func logIPCDeprecatedAlias(log *slog.Logger, oldKey, newKey, oldValue, newValue string) {
	if oldValue == "" {
		return
	}
	if newValue != "" && oldValue != newValue {
		log.Warn("deprecated IPC config key ignored because new key is set",
			"old_key", oldKey,
			"new_key", newKey,
			"old_value", oldValue,
			"new_value", newValue,
		)
		return
	}
	log.Warn("deprecated IPC config key in use",
		"old_key", oldKey,
		"new_key", newKey,
		"value", oldValue,
	)
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

func setUint8(value string, dst *uint8, section, key string) error {
	n, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return fmt.Errorf("%s.%s must be a non-negative integer 0-255: %w", section, key, err)
	}
	*dst = uint8(n)
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
