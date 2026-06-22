package api

import "time"

// ClientSummary is the /clients list/detail entry shape.
type ClientSummary struct {
	IMSI    string `json:"imsi"`
	UEIP    string `json:"ue_ip"`
	OuterIP string `json:"outer_ip"`
	APN     string `json:"apn"`
	State   string `json:"state"`
}

// IKESADetail is the IKE SA portion of a session detail response.
type IKESADetail struct {
	SPII string `json:"spi_i"`
	SPIR string `json:"spi_r"`
}

// ChildSADetail is the ESP CHILD SA portion of a session detail response.
type ChildSADetail struct {
	ESPSPIIn  string `json:"esp_spi_in"`
	ESPSPIOut string `json:"esp_spi_out"`
}

// S2BDetail is the S2b/PGW portion of a session detail response.
type S2BDetail struct {
	PGW         string `json:"pgw"`
	ControlTEID uint32 `json:"control_teid"`
	DataTEID    uint32 `json:"data_teid"`
}

// SessionDetail is the /sessions/{imsi} response shape.
type SessionDetail struct {
	IMSI    string        `json:"imsi"`
	UEIP    string        `json:"ue_ip"`
	OuterIP string        `json:"outer_ip"`
	APN     string        `json:"apn"`
	State   string        `json:"state"`
	IKESA   IKESADetail   `json:"ike_sa"`
	ChildSA ChildSADetail `json:"child_sa"`
	S2B     *S2BDetail    `json:"s2b,omitempty"`
}

// BearerDiag describes one GTP-U bearer (default or dedicated) in the diag response.
type BearerDiag struct {
	EBI             uint8     `json:"ebi"`
	LocalTEID       uint32    `json:"local_teid"`
	PGWTEID         uint32    `json:"pgw_teid"`
	QCI             uint8     `json:"qci"`
	UplinkPackets   uint64    `json:"uplink_packets"`
	UplinkBytes     uint64    `json:"uplink_bytes"`
	DownlinkPackets uint64    `json:"downlink_packets"`
	DownlinkBytes   uint64    `json:"downlink_bytes"`
	LastUplink      time.Time `json:"last_uplink_packet,omitzero"`
	LastDownlink    time.Time `json:"last_downlink_packet,omitzero"`
}

// ClientDiag is the /clients/{imsi}/diag response shape — the primary
// troubleshooting endpoint described in docs/api_handoff.md.
type ClientDiag struct {
	IMSI             string       `json:"imsi"`
	UEIP             string       `json:"ue_ip"`
	OuterIP          string       `json:"outer_ip"`
	APN              string       `json:"apn"`
	State            string       `json:"state"`
	IKESPII          string       `json:"ike_spi_i"`
	IKESPIR          string       `json:"ike_spi_r"`
	ESPSPIIn         string       `json:"esp_spi_in"`
	ESPSPIOut        string       `json:"esp_spi_out"`
	PGWControlIP     string       `json:"pgw_control_ip,omitempty"`
	PGWControlTEID   uint32       `json:"pgw_control_teid,omitempty"`
	DefaultBearer    *BearerDiag  `json:"default_bearer,omitempty"`
	DedicatedBearers []BearerDiag `json:"dedicated_bearers"`
	LastActivity     time.Time    `json:"last_activity"`
}

// HealthResponse is the /health response shape.
type HealthResponse struct {
	Status string `json:"status"`
}

// StatusResponse is the /status response shape.
type StatusResponse struct {
	Version       string `json:"version"`
	BuildDate     string `json:"build_date"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	ActiveClients int    `json:"active_clients"`
}

// StatsResponse is the /stats response shape.
type StatsResponse struct {
	ActiveClients  int `json:"active_clients"`
	ActiveIKESAs   int `json:"active_ike_sas"`
	ActiveChildSAs int `json:"active_child_sas"`
	ActiveBearers  int `json:"active_bearers"`
}

// BPFStatsResponse is the /stats/bpf response shape. Unlike the illustrative
// payload in docs/api_handoff.md, this reports the counters that actually
// exist in this codebase's BPF programs (XDP downlink decap + TC uplink
// encap) rather than fabricating fields like tft_matches/tft_misses that
// have no backing counter yet.
type BPFStatsResponse struct {
	XDPDownlink  map[string]uint64 `json:"xdp_downlink"`
	TCUplink     map[string]uint64 `json:"tc_uplink"`
	MapOccupancy map[string]int    `json:"map_occupancy"`
}

// GTPUStatsResponse is the /stats/gtpu response shape.
type GTPUStatsResponse struct {
	DownlinkRxPackets           uint64 `json:"downlink_rx_packets"`
	DownlinkTxPackets           uint64 `json:"downlink_tx_packets"`
	DroppedBadTEID              uint64 `json:"dropped_bad_teid"`
	DroppedBadPeer              uint64 `json:"dropped_bad_peer"`
	DroppedUnsupported          uint64 `json:"dropped_unsupported"`
	DroppedMalformed            uint64 `json:"dropped_malformed"`
	ErrorIndicationsSent        uint64 `json:"error_indications_sent"`
	ErrorIndicationsRateLimited uint64 `json:"error_indications_rate_limited"`
	UplinkRxPackets             uint64 `json:"uplink_rx_packets"`
	UplinkTxPackets             uint64 `json:"uplink_tx_packets"`
	ActiveTunnels               int    `json:"active_tunnels"`
	ActiveBearers               int    `json:"active_bearers"`
}

// IPsecStatsResponse is the /stats/ipsec response shape.
type IPsecStatsResponse struct {
	ActiveIKESAs   int    `json:"active_ike_sas"`
	ActiveChildSAs int    `json:"active_child_sas"`
	ESPPacketsIn   uint64 `json:"esp_packets_in"`
	ESPPacketsOut  uint64 `json:"esp_packets_out"`
	ESPBytesIn     uint64 `json:"esp_bytes_in"`
	ESPBytesOut    uint64 `json:"esp_bytes_out"`
}
