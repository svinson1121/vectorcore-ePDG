package config

import "testing"

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load("../../config/epdg.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.EPDG.Name != "epdg2.epc.mnc435.mcc311.3gppnetwork.org" {
		t.Fatalf("EPDG.Name = %q", cfg.EPDG.Name)
	}
	if SWMApplicationID != 16777264 {
		t.Fatalf("SWMApplicationID = %d", SWMApplicationID)
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
	if cfg.APN.Default != "ims" {
		t.Fatalf("APN.Default = %q", cfg.APN.Default)
	}
	if cfg.SWM.Proto != "sctp" {
		t.Fatalf("SWM.Proto = %q", cfg.SWM.Proto)
	}
	if cfg.SWM.WatchdogIntervalSeconds != 30 || cfg.SWM.WatchdogTimeoutSeconds != 10 {
		t.Fatalf("SWM watchdog = %d/%d", cfg.SWM.WatchdogIntervalSeconds, cfg.SWM.WatchdogTimeoutSeconds)
	}
	if !cfg.PCO.Enabled || !cfg.PCO.RequestDNSv4 || cfg.PCO.RequestDNSv6 || !cfg.PCO.RequestPCSCFv4 || cfg.PCO.RequestPCSCFv6 || !cfg.PCO.IncludeAPCO || cfg.PCO.StrictDecode {
		t.Fatalf("PCO config = %+v", cfg.PCO)
	}
}

func TestValidateRejectsUnsupportedSWMProto(t *testing.T) {
	cfg, err := Load("../../config/epdg.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.SWM.Proto = "udp"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("Validate() succeeded with unsupported SWm proto")
	}
}

func TestValidateAcceptsTCPSWMProto(t *testing.T) {
	cfg, err := Load("../../config/epdg.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	cfg.SWM.Proto = "tcp"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected tcp SWm proto: %v", err)
	}
}
