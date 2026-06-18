// Package api implements the read-only Huma administrative API described in
// docs/api_handoff.md. It only reads from the session store and the GTP-U/
// XFRM managers — it must never call any state-mutating method on them.
package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/gtpu"
	"vectorcore-epdg/internal/session"
)

const basePath = "/api/v1"

// BuildInfo carries the binary's version metadata into the /status endpoint.
type BuildInfo struct {
	Version   string
	BuildDate string
}

// sessionStore is the subset of *session.Manager the API reads from.
type sessionStore interface {
	Snapshot() []*session.Session
	FindByIMSIAPN(imsi, apn string) *session.Session
}

// gtpuStore is the subset of *gtpu.Manager the API reads from.
type gtpuStore interface {
	SessionSnapshot(sessionID string) (gtpu.Session, bool)
	Stats() gtpu.DataplaneStats
	XDPCounters() map[string]uint64
	TCCounters() map[string]uint64
	BPFMapOccupancy() map[string]int
	ActiveSessionCount() int
}

// Server hosts the administrative API's HTTP listener.
type Server struct {
	cfg       config.APIConfig
	sessions  sessionStore
	gtpu      gtpuStore
	build     BuildInfo
	log       *slog.Logger
	httpSrv   *http.Server
	startedAt time.Time
}

// NewServer constructs an API server. It does not start listening until Start is called.
func NewServer(cfg config.APIConfig, sessions sessionStore, gtpuMgr gtpuStore, build BuildInfo, log *slog.Logger) *Server {
	return &Server{
		cfg:      cfg,
		sessions: sessions,
		gtpu:     gtpuMgr,
		build:    build,
		log:      log,
	}
}

// Start builds the route table and begins serving HTTP in the background.
// Matches the Start(ctx) error convention used by the gtpu/s2b/swm components.
func (s *Server) Start(ctx context.Context) error {
	s.startedAt = time.Now()

	mux := http.NewServeMux()
	humaConfig := huma.DefaultConfig("VectorCore ePDG Administrative API", s.build.Version)
	humaAPI := humago.New(mux, humaConfig)

	s.registerHealth(humaAPI)
	s.registerClients(humaAPI)
	s.registerSessions(humaAPI)
	s.registerStats(humaAPI)

	addr := fmt.Sprintf("%s:%d", s.cfg.ListenAddress, s.cfg.ListenPort)
	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: corsMiddleware(mux),
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("admin API: listen %s: %w", addr, err)
	}

	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("admin API server stopped unexpectedly", "error", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the HTTP listener.
func (s *Server) Stop() error {
	if s.httpSrv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.httpSrv.Shutdown(ctx)
}

// corsMiddleware allows browser-based tooling (e.g. the Swagger/docs UI, or a
// future dashboard) to call this read-only, unauthenticated API from any origin.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) registerHealth(api huma.API) {
	huma.Get(api, basePath+"/health", func(ctx context.Context, _ *struct{}) (*struct{ Body HealthResponse }, error) {
		return &struct{ Body HealthResponse }{HealthResponse{Status: "ok"}}, nil
	})

	huma.Get(api, basePath+"/status", func(ctx context.Context, _ *struct{}) (*struct{ Body StatusResponse }, error) {
		active := 0
		for _, sess := range s.sessions.Snapshot() {
			if sess.State == session.StateActive {
				active++
			}
		}
		resp := StatusResponse{
			Version:       s.build.Version,
			BuildDate:     s.build.BuildDate,
			UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
			ActiveClients: active,
		}
		return &struct{ Body StatusResponse }{resp}, nil
	})
}
