package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func (c *Config) Validate() error {
	var errs []error
	require(&errs, c.EPDG.Name, "epdg.name")
	require(&errs, c.EPDG.Realm, "epdg.realm")
	require(&errs, c.EPDG.MCC, "epdg.mcc")
	require(&errs, c.EPDG.MNC, "epdg.mnc")
	if c.EPDG.MNCLength != 2 && c.EPDG.MNCLength != 3 {
		errs = append(errs, fmt.Errorf("epdg.mnc_length must be 2 or 3"))
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Errorf("logging.level must be one of debug, info, warn, error"))
	}

	require(&errs, c.IPC.EPDGRequestSocket, "ipc.epdg_request_socket")

	requireIP(&errs, c.SWM.LocalAddr, "swm.local_addr")
	requireIP(&errs, c.SWM.PeerAddr, "swm.peer_addr")
	requirePort(&errs, c.SWM.PeerPort, "swm.peer_port")
	switch strings.ToLower(c.SWM.Proto) {
	case "tcp", "sctp":
	default:
		errs = append(errs, fmt.Errorf("swm.proto must be tcp or sctp"))
	}
	if c.SWM.WatchdogIntervalSeconds <= 0 {
		errs = append(errs, fmt.Errorf("swm.watchdog_interval_seconds must be greater than 0"))
	}
	if c.SWM.WatchdogTimeoutSeconds <= 0 {
		errs = append(errs, fmt.Errorf("swm.watchdog_timeout_seconds must be greater than 0"))
	}
	require(&errs, c.SWM.OriginHost, "swm.origin_host")
	require(&errs, c.SWM.OriginRealm, "swm.origin_realm")
	require(&errs, c.SWM.DestinationRealm, "swm.destination_realm")

	requireIP(&errs, c.GTP.LocalGTPC, "gtp.local_gtpc")
	requireIP(&errs, c.GTP.LocalGTPU, "gtp.local_gtpu")
	requirePort(&errs, c.GTP.LocalPort, "gtp.local_port")
	requireIP(&errs, c.GTP.PGWGTPC, "gtp.pgw_gtpc")
	requireIP(&errs, c.GTP.PGWGTPU, "gtp.pgw_gtpu")
	require(&errs, c.GTP.TunName, "gtp.tun_name")
	if c.GTP.MTU < 576 || c.GTP.MTU > 9000 {
		errs = append(errs, fmt.Errorf("gtp.mtu must be between 576 and 9000"))
	}
	switch c.GTP.UplinkCapture.Mode {
	case "nfqueue":
	default:
		errs = append(errs, fmt.Errorf("gtp.uplink_capture_mode must be nfqueue"))
	}
	if c.GTP.UplinkCapture.QueueNum < 0 || c.GTP.UplinkCapture.QueueNum > 65535 {
		errs = append(errs, fmt.Errorf("gtp.nfqueue_queue_num must be between 0 and 65535"))
	}
	switch c.GTP.UplinkCapture.FirewallBackend {
	case "iptables":
	default:
		errs = append(errs, fmt.Errorf("gtp.nfqueue_firewall_backend must be iptables"))
	}
	require(&errs, c.GTP.UplinkCapture.ChainName, "gtp.nfqueue_chain_name")

	require(&errs, c.APN.Default, "apn.default")

	if c.Datapath.UplinkPolicyRoutingEnabled {
		if c.Datapath.UplinkTableID <= 0 {
			errs = append(errs, fmt.Errorf("datapath.uplink_table_id must be greater than 0"))
		}
		if c.Datapath.UplinkPriorityBase <= 0 {
			errs = append(errs, fmt.Errorf("datapath.uplink_priority_base must be greater than 0"))
		}
	}
	switch c.Reauth.Mode {
	case "preserve_existing_s2b", "detach_new_attach":
	default:
		errs = append(errs, fmt.Errorf("reauth.mode must be preserve_existing_s2b or detach_new_attach"))
	}
	switch c.Reauth.OnFailure {
	case "keep_existing_until_ipsec_delete", "delete_existing_session":
	default:
		errs = append(errs, fmt.Errorf("reauth.on_failure must be keep_existing_until_ipsec_delete or delete_existing_session"))
	}
	if c.Shutdown.TimeoutSeconds <= 0 {
		errs = append(errs, fmt.Errorf("shutdown.timeout_seconds must be greater than 0"))
	}

	return errors.Join(errs...)
}

func require(errs *[]error, value, name string) {
	if value == "" {
		*errs = append(*errs, fmt.Errorf("%s is required", name))
	}
}

func requireIP(errs *[]error, value, name string) {
	require(errs, value, name)
	if value != "" && net.ParseIP(value) == nil {
		*errs = append(*errs, fmt.Errorf("%s must be an IP address", name))
	}
}

func requirePort(errs *[]error, value int, name string) {
	if value <= 0 || value > 65535 {
		*errs = append(*errs, fmt.Errorf("%s must be between 1 and 65535", name))
	}
}
