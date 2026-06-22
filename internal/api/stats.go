package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-epdg/internal/session"
	"vectorcore-epdg/internal/xfrm"
)

func (s *Server) registerStats(api huma.API) {
	huma.Get(api, basePath+"/stats", func(ctx context.Context, _ *struct{}) (*struct{ Body StatsResponse }, error) {
		sessions := s.sessions.Snapshot()
		resp := StatsResponse{
			ActiveBearers: s.activeBearerCount(sessions),
		}
		for _, sess := range sessions {
			sess.RLock()
			if sess.State == session.StateActive {
				resp.ActiveClients++
			}
			if sess.IkeSPII != 0 {
				resp.ActiveIKESAs++
			}
			if sess.ESPInboundSPI != 0 {
				resp.ActiveChildSAs++
			}
			sess.RUnlock()
		}
		return &struct{ Body StatsResponse }{resp}, nil
	})

	huma.Get(api, basePath+"/stats/bpf", func(ctx context.Context, _ *struct{}) (*struct{ Body BPFStatsResponse }, error) {
		resp := BPFStatsResponse{
			XDPDownlink:  s.gtpu.XDPCounters(),
			TCUplink:     s.gtpu.TCCounters(),
			MapOccupancy: s.gtpu.BPFMapOccupancy(),
		}
		return &struct{ Body BPFStatsResponse }{resp}, nil
	})

	huma.Get(api, basePath+"/stats/gtpu", func(ctx context.Context, _ *struct{}) (*struct{ Body GTPUStatsResponse }, error) {
		dpStats := s.gtpu.Stats()
		tc := s.gtpu.TCCounters()
		xdp := s.gtpu.XDPCounters()
		resp := GTPUStatsResponse{
			DownlinkRxPackets:           xdp["seen"],
			DownlinkTxPackets:           xdp["decap_pass"],
			DroppedBadTEID:              xdp["teid_miss"],
			DroppedBadPeer:              dpStats.DroppedBadPeer,
			DroppedUnsupported:          dpStats.DroppedUnsupported,
			DroppedMalformed:            dpStats.DroppedMalformed,
			ErrorIndicationsSent:        dpStats.ErrorIndicationsSent,
			ErrorIndicationsRateLimited: dpStats.ErrorIndicationsRateLimited,
			UplinkRxPackets:             tc["seen"],
			UplinkTxPackets:             tc["encap_ok"],
			ActiveTunnels:               s.gtpu.ActiveSessionCount(),
			ActiveBearers:               s.activeBearerCount(s.sessions.Snapshot()),
		}
		return &struct{ Body GTPUStatsResponse }{resp}, nil
	})

	huma.Get(api, basePath+"/stats/ipsec", func(ctx context.Context, _ *struct{}) (*struct{ Body IPsecStatsResponse }, error) {
		espStats, err := xfrm.Stats()
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to read XFRM stats", err)
		}
		sessions := s.sessions.Snapshot()
		resp := IPsecStatsResponse{
			ESPPacketsIn:  espStats.PacketsIn,
			ESPPacketsOut: espStats.PacketsOut,
			ESPBytesIn:    espStats.BytesIn,
			ESPBytesOut:   espStats.BytesOut,
		}
		for _, sess := range sessions {
			sess.RLock()
			if sess.IkeSPII != 0 {
				resp.ActiveIKESAs++
			}
			if sess.ESPInboundSPI != 0 {
				resp.ActiveChildSAs++
			}
			sess.RUnlock()
		}
		return &struct{ Body IPsecStatsResponse }{resp}, nil
	})
}

// activeBearerCount sums the number of GTP-U bearers installed across all
// sessions known to the session store.
func (s *Server) activeBearerCount(sessions []*session.Session) int {
	total := 0
	for _, sess := range sessions {
		gtpuSess, ok := s.gtpu.SessionSnapshot(sess.ID)
		if !ok {
			continue
		}
		total += len(gtpuSess.Bearers)
	}
	return total
}
