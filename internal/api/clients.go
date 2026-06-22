package api

import (
	"context"
	"fmt"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-epdg/internal/gtpu"
	"vectorcore-epdg/internal/session"
)

type imsiInput struct {
	IMSI string `path:"imsi" doc:"Subscriber IMSI"`
}

func (s *Server) registerClients(api huma.API) {
	huma.Get(api, basePath+"/clients", func(ctx context.Context, _ *struct{}) (*struct{ Body []ClientSummary }, error) {
		var out []ClientSummary
		for _, sess := range s.sessions.Snapshot() {
			out = append(out, clientSummary(sess))
		}
		return &struct{ Body []ClientSummary }{out}, nil
	})

	huma.Get(api, basePath+"/clients/{imsi}", func(ctx context.Context, in *imsiInput) (*struct{ Body ClientSummary }, error) {
		sess := s.sessions.FindByIMSIAPN(in.IMSI, "")
		if sess == nil {
			return nil, huma.Error404NotFound(fmt.Sprintf("no client found for IMSI %s", in.IMSI))
		}
		return &struct{ Body ClientSummary }{clientSummary(sess)}, nil
	})

	huma.Get(api, basePath+"/clients/{imsi}/diag", func(ctx context.Context, in *imsiInput) (*struct{ Body ClientDiag }, error) {
		sess := s.sessions.FindByIMSIAPN(in.IMSI, "")
		if sess == nil {
			return nil, huma.Error404NotFound(fmt.Sprintf("no client found for IMSI %s", in.IMSI))
		}
		return &struct{ Body ClientDiag }{s.clientDiag(sess)}, nil
	})
}

func clientSummary(sess *session.Session) ClientSummary {
	sess.RLock()
	defer sess.RUnlock()
	ueIP := ""
	if sess.S2B != nil {
		ueIP = sess.S2B.PAA
	}
	return ClientSummary{
		IMSI:    sess.IMSI,
		UEIP:    ueIP,
		OuterIP: sess.OuterIP,
		APN:     sess.APN,
		State:   string(sess.State),
	}
}

func (s *Server) clientDiag(sess *session.Session) ClientDiag {
	sess.RLock()
	out := ClientDiag{
		IMSI:         sess.IMSI,
		OuterIP:      sess.OuterIP,
		APN:          sess.APN,
		State:        string(sess.State),
		IKESPII:      fmt.Sprintf("0x%x", sess.IkeSPII),
		IKESPIR:      fmt.Sprintf("0x%x", sess.IkeSPIR),
		ESPSPIIn:     fmt.Sprintf("0x%x", sess.ESPInboundSPI),
		ESPSPIOut:    fmt.Sprintf("0x%x", sess.ESPOutboundSPI),
		LastActivity: sess.UpdatedAt,
	}
	if sess.S2B != nil {
		out.UEIP = sess.S2B.PAA
		if sess.S2B.PGWControlIP != nil {
			out.PGWControlIP = sess.S2B.PGWControlIP.String()
		}
		out.PGWControlTEID = sess.S2B.PGWControlTEID
	}
	sess.RUnlock()

	gtpuSess, ok := s.gtpu.SessionSnapshot(sess.ID)
	if !ok {
		return out
	}
	for ebi, b := range gtpuSess.Bearers {
		diag := bearerDiag(b)
		if ebi == gtpuSess.DefaultEBI {
			out.DefaultBearer = &diag
			continue
		}
		out.DedicatedBearers = append(out.DedicatedBearers, diag)
	}
	return out
}

func bearerDiag(b *gtpu.Bearer) BearerDiag {
	return BearerDiag{
		EBI:             b.EBI,
		LocalTEID:       b.LocalRXTEID,
		PGWTEID:         b.RemoteTXTEID,
		QCI:             b.QoS.QCI,
		UplinkPackets:   b.Counters.UplinkPackets,
		UplinkBytes:     b.Counters.UplinkBytes,
		DownlinkPackets: b.Counters.DownlinkPackets,
		DownlinkBytes:   b.Counters.DownlinkBytes,
		LastUplink:      b.Counters.LastUplinkPacket,
		LastDownlink:    b.Counters.LastDownlinkPacket,
	}
}
