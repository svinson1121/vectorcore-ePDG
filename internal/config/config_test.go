package config

import "testing"

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load("../../configs/epdg.yaml.example")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.EPDG.Name != "epdg.epc.mnc435.mcc311.3gppnetwork.org" {
		t.Fatalf("EPDG.Name = %q", cfg.EPDG.Name)
	}
	if SWMApplicationID != 16777264 {
		t.Fatalf("SWMApplicationID = %d", SWMApplicationID)
	}
	if cfg.GTP.TunName != "vc-gtpu0" {
		t.Fatalf("GTP.TunName = %q", cfg.GTP.TunName)
	}
	if cfg.GTP.LocalPort != 2152 {
		t.Fatalf("GTP.LocalPort = %d", cfg.GTP.LocalPort)
	}
	if cfg.GTP.MTU != 1400 {
		t.Fatalf("GTP.MTU = %d", cfg.GTP.MTU)
	}
	if !cfg.GTP.StrictPeerCheck {
		t.Fatalf("GTP.StrictPeerCheck = false")
	}
	if cfg.APN.Default != "internet" {
		t.Fatalf("APN.Default = %q", cfg.APN.Default)
	}
	if cfg.SWM.Proto != "sctp" {
		t.Fatalf("SWM.Proto = %q", cfg.SWM.Proto)
	}
	if cfg.SWM.WatchdogIntervalSeconds != 30 || cfg.SWM.WatchdogTimeoutSeconds != 10 {
		t.Fatalf("SWM watchdog = %d/%d", cfg.SWM.WatchdogIntervalSeconds, cfg.SWM.WatchdogTimeoutSeconds)
	}
	if !cfg.Datapath.RequirePAAIPsecAlign {
		t.Fatalf("Datapath.RequirePAAIPsecAlign = false")
	}
	if cfg.Datapath.UplinkPolicyRoutingEnabled {
		t.Fatalf("Datapath.UplinkPolicyRoutingEnabled = true")
	}
	if cfg.GTP.UplinkCapture.Mode != "nfqueue" {
		t.Fatalf("GTP.UplinkCapture.Mode = %q", cfg.GTP.UplinkCapture.Mode)
	}
	if cfg.GTP.UplinkCapture.QueueNum != 4200 {
		t.Fatalf("GTP.UplinkCapture.QueueNum = %d", cfg.GTP.UplinkCapture.QueueNum)
	}
	if !cfg.GTP.UplinkCapture.InstallRules || cfg.GTP.UplinkCapture.FirewallBackend != "iptables" || cfg.GTP.UplinkCapture.ChainName != "VECTORCORE-EPDG-UPLINK" {
		t.Fatalf("GTP.UplinkCapture = %+v", cfg.GTP.UplinkCapture)
	}
	if cfg.Datapath.UplinkPriorityBase != 10000 {
		t.Fatalf("Datapath.UplinkPriorityBase = %d", cfg.Datapath.UplinkPriorityBase)
	}
	if !cfg.PCO.Enabled || !cfg.PCO.RequestDNS || !cfg.PCO.RequestPCSCF || cfg.PCO.RequestMTU || !cfg.PCO.IncludeAPCO || cfg.PCO.StrictDecode {
		t.Fatalf("PCO config = %+v", cfg.PCO)
	}
	if cfg.IPC.EPDGRequestSocket != "/run/vectorcore/epdg-eap.sock" {
		t.Fatalf("IPC.EPDGRequestSocket = %q", cfg.IPC.EPDGRequestSocket)
	}
	if cfg.IPC.PluginControlSocket != "/run/vectorcore/strongswan-eap.sock" {
		t.Fatalf("IPC.PluginControlSocket = %q", cfg.IPC.PluginControlSocket)
	}
	if cfg.Reauth.Mode != "preserve_existing_s2b" {
		t.Fatalf("Reauth.Mode = %q", cfg.Reauth.Mode)
	}
	if cfg.Reauth.AllowFallbackNewAttach {
		t.Fatalf("Reauth.AllowFallbackNewAttach = true")
	}
	if cfg.Reauth.OnFailure != "keep_existing_until_ipsec_delete" {
		t.Fatalf("Reauth.OnFailure = %q", cfg.Reauth.OnFailure)
	}
}

func TestLegacyIPCAliases(t *testing.T) {
	cfg := Default()
	cfg.IPC.EPDGRequestSocket = ""
	cfg.IPC.PluginControlSocket = ""
	cfg.IPC.Listen = "/tmp/legacy-epdg.sock"
	cfg.IPC.PluginControl = "/tmp/legacy-plugin.sock"
	cfg.ResolveLegacyAliases()
	if cfg.IPC.EPDGRequestSocket != "/tmp/legacy-epdg.sock" {
		t.Fatalf("EPDGRequestSocket = %q", cfg.IPC.EPDGRequestSocket)
	}
	if cfg.IPC.PluginControlSocket != "/tmp/legacy-plugin.sock" {
		t.Fatalf("PluginControlSocket = %q", cfg.IPC.PluginControlSocket)
	}
}

func TestNewIPCKeysWinOverLegacyAliases(t *testing.T) {
	cfg := Default()
	cfg.IPC.EPDGRequestSocket = "/tmp/new-epdg.sock"
	cfg.IPC.PluginControlSocket = "/tmp/new-plugin.sock"
	cfg.IPC.Listen = "/tmp/old-epdg.sock"
	cfg.IPC.PluginControl = "/tmp/old-plugin.sock"
	cfg.ResolveLegacyAliases()
	if cfg.IPC.EPDGRequestSocket != "/tmp/new-epdg.sock" {
		t.Fatalf("EPDGRequestSocket = %q", cfg.IPC.EPDGRequestSocket)
	}
	if cfg.IPC.PluginControlSocket != "/tmp/new-plugin.sock" {
		t.Fatalf("PluginControlSocket = %q", cfg.IPC.PluginControlSocket)
	}
}

func TestValidateRejectsUnsupportedSWMProto(t *testing.T) {
	cfg, err := Load("../../configs/epdg.yaml.example")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.SWM.Proto = "udp"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() succeeded with unsupported SWm proto")
	}
}

func TestValidateAcceptsTCPSWMProto(t *testing.T) {
	cfg, err := Load("../../configs/epdg.yaml.example")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.SWM.Proto = "tcp"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected tcp SWm proto: %v", err)
	}
}
