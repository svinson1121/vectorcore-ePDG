package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"vectorcore-epdg/internal/gtpu"
	"vectorcore-epdg/internal/session"
)

// fakeSessions implements sessionStore for tests.
type fakeSessions struct {
	sessions []*session.Session
}

func (f *fakeSessions) Snapshot() []*session.Session { return f.sessions }

func (f *fakeSessions) FindByIMSIAPN(imsi, apn string) *session.Session {
	for _, sess := range f.sessions {
		if sess.IMSI == imsi && (apn == "" || sess.APN == apn) {
			return sess
		}
	}
	return nil
}

// fakeGTPU implements gtpuStore for tests.
type fakeGTPU struct {
	sessions map[string]gtpu.Session
}

func (f *fakeGTPU) SessionSnapshot(id string) (gtpu.Session, bool) {
	sess, ok := f.sessions[id]
	return sess, ok
}
func (f *fakeGTPU) Stats() gtpu.DataplaneStats      { return gtpu.DataplaneStats{DownlinkGTPUIn: 42} }
func (f *fakeGTPU) XDPCounters() map[string]uint64  { return map[string]uint64{"seen": 1} }
func (f *fakeGTPU) TCCounters() map[string]uint64   { return map[string]uint64{"encap_ok": 2} }
func (f *fakeGTPU) BPFMapOccupancy() map[string]int { return map[string]int{"teid_map_entries": 1} }
func (f *fakeGTPU) ActiveSessionCount() int         { return len(f.sessions) }

func newTestServer(t *testing.T) *Server {
	t.Helper()
	sess := session.New("sess-1")
	sess.IMSI = "311435300070581"
	sess.APN = "ims"
	sess.State = session.StateActive
	sess.OuterIP = "203.0.113.5:500"
	sess.IkeSPII = 0x1111
	sess.IkeSPIR = 0x2222
	sess.ESPInboundSPI = 0x3333
	sess.ESPOutboundSPI = 0x4444
	sess.S2B = &session.S2BContext{
		PAA:            "100.64.0.10",
		PGWControlTEID: 1001,
		PGWUserTEID:    1002,
	}

	gtpuSess := gtpu.Session{
		ID:         sess.ID,
		DefaultEBI: 5,
		Bearers: map[uint8]*gtpu.Bearer{
			5: {EBI: 5, LocalRXTEID: 10, RemoteTXTEID: 20, Counters: gtpu.BearerCounters{UplinkPackets: 7}},
		},
	}

	srv := &Server{
		sessions:  &fakeSessions{sessions: []*session.Session{sess}},
		gtpu:      &fakeGTPU{sessions: map[string]gtpu.Session{sess.ID: gtpuSess}},
		build:     BuildInfo{Version: "test"},
		startedAt: time.Now(),
	}

	mux := http.NewServeMux()
	humaAPI := humago.New(mux, huma.DefaultConfig("test", "1.0.0"))
	srv.registerHealth(humaAPI)
	srv.registerClients(humaAPI)
	srv.registerSessions(humaAPI)
	srv.registerStats(humaAPI)
	srv.httpSrv = &http.Server{Handler: mux}
	return srv
}

func doGet(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.httpSrv.Handler.ServeHTTP(rec, req)
	return rec
}

func TestHealth(t *testing.T) {
	srv := newTestServer(t)
	rec := doGet(t, srv, "/api/v1/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" {
		t.Fatalf("status = %q", body.Status)
	}
}

func TestClientsList(t *testing.T) {
	srv := newTestServer(t)
	rec := doGet(t, srv, "/api/v1/clients")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body []ClientSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body[0].IMSI != "311435300070581" || body[0].UEIP != "100.64.0.10" {
		t.Fatalf("unexpected body: %+v", body)
	}
}

func TestClientNotFound(t *testing.T) {
	srv := newTestServer(t)
	rec := doGet(t, srv, "/api/v1/clients/000000000000000")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestClientDiag(t *testing.T) {
	srv := newTestServer(t)
	rec := doGet(t, srv, "/api/v1/clients/311435300070581/diag")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body ClientDiag
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.DefaultBearer == nil || body.DefaultBearer.LocalTEID != 10 {
		t.Fatalf("unexpected diag body: %+v", body)
	}
	if body.ESPSPIIn != "0x3333" {
		t.Fatalf("esp_spi_in = %q", body.ESPSPIIn)
	}
}

func TestSessionDetail(t *testing.T) {
	srv := newTestServer(t)
	rec := doGet(t, srv, "/api/v1/sessions/311435300070581")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body SessionDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.IKESA.SPII != "0x1111" || body.S2B == nil || body.S2B.ControlTEID != 1001 {
		t.Fatalf("unexpected session body: %+v", body)
	}
}

func TestStats(t *testing.T) {
	srv := newTestServer(t)
	rec := doGet(t, srv, "/api/v1/stats")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body StatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ActiveClients != 1 || body.ActiveBearers != 1 {
		t.Fatalf("unexpected stats body: %+v", body)
	}
}

func TestStatsBPF(t *testing.T) {
	srv := newTestServer(t)
	rec := doGet(t, srv, "/api/v1/stats/bpf")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body BPFStatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.XDPDownlink["seen"] != 1 || body.TCUplink["encap_ok"] != 2 {
		t.Fatalf("unexpected bpf stats body: %+v", body)
	}
}
