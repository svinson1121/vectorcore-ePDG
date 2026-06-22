package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"vectorcore-epdg/internal/api"
	"vectorcore-epdg/internal/config"
	"vectorcore-epdg/internal/cpucaps"
	"vectorcore-epdg/internal/gtpu"
	"vectorcore-epdg/internal/ikev2"
	"vectorcore-epdg/internal/logging"
	"vectorcore-epdg/internal/s2b"
	"vectorcore-epdg/internal/session"
	"vectorcore-epdg/internal/swm"
	"vectorcore-epdg/internal/xfrm"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	var cfgPath string
	var debug bool
	var validateOnly bool
	var showVersion bool

	flag.StringVar(&cfgPath, "c", config.DefaultPath, "path to ePDG YAML config")
	flag.BoolVar(&debug, "d", false, "enable debug console logging")
	flag.BoolVar(&validateOnly, "validate", false, "load and validate config, then exit")
	flag.BoolVar(&showVersion, "v", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Fprint(os.Stdout, buildInfo())
		return
	}

	fmt.Fprintf(os.Stdout, "Starting VectorCore ePDG %s\n", version)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VectorCore ePDG: %v\n", err)
		os.Exit(1)
	}
	if validateOnly {
		fmt.Printf("config valid: %s\n", cfgPath)
		return
	}

	log, err := logging.New(cfg.Logging, debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VectorCore ePDG: %v\n", err)
		os.Exit(1)
	}
	defer log.Close() //nolint:errcheck

	log.Info("VectorCore ePDG starting",
		"identity", cfg.EPDG.Name,
		"realm", cfg.EPDG.Realm,
		"mcc", cfg.EPDG.MCC,
		"mnc", cfg.EPDG.MNC,
		"version", version,
		"build_date", buildDate,
	)

	caps := cpucaps.Detect()
	kernelAESNI, err := cpucaps.KernelXFRMUsesAESNI()
	if err != nil {
		log.Warn("CPU caps: could not verify kernel XFRM AES-NI", "error", err)
	}
	caps.Log(log.Logger, kernelAESNI)

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		sig := <-sigCh
		log.Info("VectorCore ePDG shutdown requested", "signal", sig.String())
		cancel()
	}()

	// Flush stale XFRM state from any previous run before installing new SAs.
	if err := xfrm.FlushAll(); err != nil {
		log.Warn("XFRM flush at startup failed (continuing)", "error", err)
	}

	manager := session.NewManager()
	_ = manager // used by s2b/gtpu handlers below

	gtpuManager := gtpu.NewManager(*cfg, log.Logger)
	if err := gtpuManager.Start(ctx); err != nil {
		log.Error("GTP-U dataplane not ready", "error", err)
		os.Exit(1)
	}

	s2bClient := s2b.NewClient(*cfg, log.Logger)
	s2bClient.SetCreateBearerHandler(func(ctx context.Context, event s2b.CreateBearerEvent) s2b.CreateBearerResult {
		return handlePGWCreateBearer(ctx, manager, gtpuManager, log.Logger, event, cfg.GTP.LocalGTPU)
	})
	s2bClient.SetUpdateBearerHandler(func(ctx context.Context, event s2b.UpdateBearerEvent) s2b.UpdateBearerResult {
		return handlePGWUpdateBearer(ctx, manager, gtpuManager, log.Logger, event)
	})
	if err := s2bClient.Start(ctx); err != nil {
		log.Warn("S2b GTPv2-C client not ready", "error", err)
	}

	swmClient := swm.NewClient(*cfg, log.Logger)
	go func() {
		if err := swmClient.Start(ctx); err != nil {
			log.Warn("SWm Diameter client not ready", "error", err)
		}
	}()

	s2bClient.SetDeleteSessionHandler(func(ctx context.Context, event s2b.DeleteSessionEvent) {
		handlePGWDelete(ctx, manager, gtpuManager, s2bClient, swmClient, log.Logger, event)
	})
	s2bClient.SetDeleteBearerHandler(func(ctx context.Context, event s2b.DeleteBearerEvent) s2b.DeleteBearerResult {
		return handlePGWDeleteBearer(ctx, manager, gtpuManager, s2bClient, log.Logger, event)
	})

	ikeSrv := ikev2.NewServer(&ikev2.Config{
		ListenAddr:   cfg.IKEv2.ListenAddr,
		ListenAddrV6: cfg.IKEv2.ListenAddrV6,
	}, log.Logger)
	if err := ikeSrv.SetFullConfig(cfg); err != nil {
		log.Error("IKEv2: cert configuration error", "error", err)
		os.Exit(1)
	}
	ikeSrv.SetSWM(swmClient)
	ikeSrv.SetSessionManager(manager)
	ikeSrv.SetS2B(s2bClient)
	ikeSrv.SetGTPU(gtpuManager)
	if err := ikeSrv.ListenAndServe(ctx); err != nil {
		log.Error("IKEv2 server failed to start", "error", err)
		os.Exit(1)
	}

	var apiSrv *api.Server
	if cfg.API.Enabled {
		apiSrv = api.NewServer(cfg.API, manager, gtpuManager, api.BuildInfo{
			Version:   version,
			BuildDate: buildDate,
		}, log.Logger)
		if err := apiSrv.Start(ctx); err != nil {
			log.Error("admin API failed to start", "error", err)
			os.Exit(1)
		}
		log.Info("admin API listening", "addr", fmt.Sprintf("%s:%d", cfg.API.ListenAddress, cfg.API.ListenPort))
	}

	log.Info("VectorCore ePDG ready",
		"ikev2_listen", cfg.IKEv2.ListenAddr,
		"swm_peer", fmt.Sprintf("%s:%d", cfg.SWM.PeerAddr, cfg.SWM.PeerPort),
		"s2b_pgw", cfg.GTP.PGWGTPC,
	)

	<-ctx.Done()

	shutdownTimeout := time.Duration(cfg.Shutdown.TimeoutSeconds) * time.Second
	log.Info("VectorCore ePDG shutdown", "timeout", shutdownTimeout)

	ikeSrv.Close()

	if apiSrv != nil {
		waitComponent(log.Logger, "admin_api", shutdownTimeout, func() error {
			return apiSrv.Stop()
		})
	}

	waitComponent(log.Logger, "gtpu_dataplane", shutdownTimeout, func() error {
		return gtpuManager.Stop()
	})
	waitComponent(log.Logger, "s2b_gtpc", shutdownTimeout, func() error {
		return s2bClient.Stop()
	})
	waitComponent(log.Logger, "swm_diameter", shutdownTimeout, func() error {
		return swmClient.Stop()
	})
	log.Info("VectorCore ePDG stopped")
}

func waitComponent(log *slog.Logger, component string, timeout time.Duration, stop func() error) {
	done := make(chan error, 1)
	go func() { done <- stop() }()
	select {
	case err := <-done:
		if err != nil {
			log.Warn("shutdown component failed", "component", component, "error", err)
		}
	case <-time.After(timeout):
		log.Error("shutdown timeout", "component", component, "waited", timeout)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// PGW-initiated event handlers (s2b callbacks)
// ────────────────────────────────────────────────────────────────────────────

func handlePGWDelete(ctx context.Context, manager *session.Manager, gtpuManager *gtpu.Manager, s2bClient *s2b.Client, swmClient *swm.Client, log *slog.Logger, event s2b.DeleteSessionEvent) {
	sess := manager.FindByLocalControlTEID(event.LocalControlTEID)
	if sess == nil {
		log.Info("PGW Delete Session matched no active session", "local_control_teid", event.LocalControlTEID)
		return
	}
	sess.RLock()
	imsi := sess.IMSI
	swmSessionID := sess.SWMSessionID
	sess.RUnlock()

	log.Info("PGW Delete Session", "session_id", sess.ID, "imsi", imsi, "is_handover", event.IsHandover)
	cleanupSession(sess, gtpuManager, s2bClient, log, "pgw_deleted", false)
	if swmClient != nil && swmSessionID != "" {
		strCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		var err error
		if event.IsHandover {
			err = swmClient.TerminateSessionHandover(strCtx, swmSessionID)
		} else {
			err = swmClient.TerminateSession(strCtx, swmSessionID)
		}
		cancel()
		if err != nil {
			log.Warn("PGW Delete: SWm STR failed", "err", err, "session_id", sess.ID)
		}
	}
	manager.Delete(sess.ID)
}

func handlePGWCreateBearer(ctx context.Context, manager *session.Manager, gtpuManager *gtpu.Manager, log *slog.Logger, event s2b.CreateBearerEvent, localGTPU string) s2b.CreateBearerResult {
	var sess *session.Session
	for attempt := 0; attempt < 10; attempt++ {
		sess = manager.FindByLocalControlTEID(event.LocalControlTEID)
		if sess != nil {
			break
		}
		select {
		case <-ctx.Done():
			return s2b.CreateBearerResult{Accepted: false, Cause: 64}
		case <-time.After(10 * time.Millisecond):
		}
	}
	if sess == nil {
		log.Warn("PGW Create Bearer matched no active session", "local_control_teid", event.LocalControlTEID)
		return s2b.CreateBearerResult{Accepted: false, Cause: 64}
	}
	sess.RLock()
	defaultEBI := uint8(0)
	pgwControlTEID := uint32(0)
	if sess.S2B != nil {
		defaultEBI = sess.S2B.EBI
		pgwControlTEID = sess.S2B.PGWControlTEID
	}
	sess.RUnlock()
	// Wait for the GTP-U session (default bearer) to be installed.
	// The PGW often sends Create Bearer Request before we've finished installing
	// the default bearer in the GTP-U manager (~8ms gap). Without this wait,
	// AddBearer returns "session not found" and we reject with cause=64, which
	// causes StarOS to tear down the entire default bearer session.
	if defaultEBI != 0 {
		for attempt := 0; attempt < 20; attempt++ {
			if gtpuManager.HasBearer(sess.ID, defaultEBI) {
				break
			}
			select {
			case <-ctx.Done():
				return s2b.CreateBearerResult{Accepted: false, Cause: 64}
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	result := s2b.CreateBearerResult{Accepted: true, Cause: 16}
	bearers := event.Bearers
	if len(bearers) == 0 {
		bearers = []s2b.CreateBearerContext{{
			EBI:         event.EBI,
			HasEBI:      event.EBI != 0,
			PGWUserTEID: event.PGWUserTEID,
			PGWUserIP:   event.PGWUserIP,
			QCI:         event.QCI,
			TFTRaw:      event.TFTRaw,
		}}
	}
	for _, bearer := range bearers {
		dedicatedEBI := bearer.EBI
		if bearer.UnassignedEBI || dedicatedEBI == 0 {
			allocated, err := allocateDedicatedEBI(gtpuManager, sess.ID, defaultEBI)
			if err != nil {
				log.Warn("PGW Create Bearer no EBI available", "session_id", sess.ID)
				result.Accepted = false
				result.Cause = 64
				result.Bearers = append(result.Bearers, s2b.CreateBearerBearerResult{EBI: 0, Accepted: false, Cause: 64})
				continue
			}
			dedicatedEBI = allocated
		} else if dedicatedEBI == defaultEBI || gtpuManager.HasBearer(sess.ID, dedicatedEBI) {
			log.Warn("PGW Create Bearer EBI collision", "session_id", sess.ID, "ebi", dedicatedEBI)
			result.Accepted = false
			result.Cause = 64
			result.Bearers = append(result.Bearers, s2b.CreateBearerBearerResult{EBI: dedicatedEBI, Accepted: false, Cause: 64})
			continue
		}
		tft, tftErr := gtpu.ParseTFT(bearer.TFTRaw)
		if tftErr != nil {
			tft = &gtpu.TFT{}
		}
		localTEID, err := allocateBearerTEID(ctx, gtpuManager, sess.ID, gtpu.Bearer{
			EBI:          dedicatedEBI,
			RemoteTXTEID: bearer.PGWUserTEID,
			PGWGTPUIP:    bearer.PGWUserIP,
			LocalGTPUIP:  net.ParseIP(localGTPU),
			QoS:          gtpu.BearerQoS{QCI: bearer.QCI},
			TFT:          tft,
		})
		if err != nil {
			log.Warn("PGW Create Bearer install failed", "session_id", sess.ID, "ebi", dedicatedEBI, "error", err)
			result.Accepted = false
			result.Cause = 64
			result.Bearers = append(result.Bearers, s2b.CreateBearerBearerResult{EBI: dedicatedEBI, Accepted: false, Cause: 64})
			continue
		}
		tftFilterCount := 0
		if tft != nil {
			tftFilterCount = len(tft.Filters)
		}
		log.Info("PGW Create Bearer installed",
			"session_id", sess.ID, "ebi", dedicatedEBI,
			"local_teid", localTEID, "pgw_teid", bearer.PGWUserTEID,
			"tft_filters", tftFilterCount)
		if result.LocalUserTEID == 0 {
			result.LocalUserTEID = localTEID
			result.LocalUserIP = net.ParseIP(localGTPU)
		}
		result.Bearers = append(result.Bearers, s2b.CreateBearerBearerResult{
			EBI:           dedicatedEBI,
			Accepted:      true,
			Cause:         16,
			LocalUserTEID: localTEID,
			LocalUserIP:   net.ParseIP(localGTPU),
			PGWUserTEID:   bearer.PGWUserTEID,
			PGWUserIP:     bearer.PGWUserIP,
			ChargingID:    bearer.ChargingID,
			HasChargingID: bearer.HasChargingID,
		})
	}
	if pgwControlTEID != 0 {
		result.PGWControlTEID = pgwControlTEID
	}
	return result
}

func handlePGWDeleteBearer(ctx context.Context, manager *session.Manager, gtpuManager *gtpu.Manager, s2bClient *s2b.Client, log *slog.Logger, event s2b.DeleteBearerEvent) s2b.DeleteBearerResult {
	sess := manager.FindByLocalControlTEID(event.LocalControlTEID)
	if sess == nil {
		log.Warn("PGW Delete Bearer matched no session", "local_control_teid", event.LocalControlTEID)
		return s2b.DeleteBearerResult{Cause: 64}
	}
	sess.RLock()
	pgwControlTEID := uint32(0)
	defaultEBI := uint8(0)
	if sess.S2B != nil {
		pgwControlTEID = sess.S2B.PGWControlTEID
		defaultEBI = sess.S2B.EBI
	}
	imsi := sess.IMSI
	sess.RUnlock()

	// PGW may send Cause=Reactivation Requested (handover) on a dedicated bearer
	// DeleteBearerReq before sending a separate one for the default bearer.
	// Capture the signal here so we act correctly when the default bearer arrives.
	if event.IsHandover {
		sess.Lock()
		if !sess.HandoverComplete {
			sess.HandoverComplete = true
			log.Info("PGW Delete Bearer: handover signal on dedicated bearer", "session_id", sess.ID, "imsi", imsi, "ebis", event.EBIs)
		}
		sess.Unlock()
	}
	for _, ebi := range event.EBIs {
		if defaultEBI != 0 && ebi == defaultEBI {
			sess.RLock()
			handoverComplete := sess.HandoverComplete
			sess.RUnlock()
			log.Info("PGW Delete Bearer default bearer", "session_id", sess.ID, "imsi", imsi, "is_handover", handoverComplete)
			if handoverComplete {
				cleanupSession(sess, gtpuManager, s2bClient, log, "pgw_delete_default_bearer", false)
				sess.Lock()
				sess.S2B = nil // prevent fullTeardown from retrying GTP-U and S2b cleanup
				sess.Unlock()
				// Session left in manager — fullTeardown sends USER_MOVED STR when UE sends IKE DELETE or DPD fires
			} else {
				cleanupSession(sess, gtpuManager, s2bClient, log, "pgw_delete_default_bearer", false)
				manager.Delete(sess.ID)
			}
			return s2b.DeleteBearerResult{Cause: 16, PGWControlTEID: pgwControlTEID}
		}
		if err := gtpuManager.RemoveBearer(ctx, sess.ID, ebi); err != nil {
			log.Warn("PGW Delete Bearer remove failed", "session_id", sess.ID, "ebi", ebi, "error", err)
			return s2b.DeleteBearerResult{Cause: 64, PGWControlTEID: pgwControlTEID}
		}
	}
	return s2b.DeleteBearerResult{Cause: 16, PGWControlTEID: pgwControlTEID}
}

func handlePGWUpdateBearer(ctx context.Context, manager *session.Manager, gtpuManager *gtpu.Manager, log *slog.Logger, event s2b.UpdateBearerEvent) s2b.UpdateBearerResult {
	sess := manager.FindByLocalControlTEID(event.LocalControlTEID)
	if sess == nil {
		log.Warn("PGW Update Bearer matched no session", "local_control_teid", event.LocalControlTEID)
		return s2b.UpdateBearerResult{Cause: 64}
	}
	sess.RLock()
	pgwControlTEID := uint32(0)
	if sess.S2B != nil {
		pgwControlTEID = sess.S2B.PGWControlTEID
	}
	sess.RUnlock()
	for _, bc := range event.Bearers {
		if !bc.HasBearerQoS && !bc.HasTFT {
			continue
		}
		if err := gtpuManager.UpdateBearer(ctx, sess.ID, bc.EBI, bc.QCI, bc.TFTRaw); err != nil {
			log.Warn("PGW Update Bearer failed", "session_id", sess.ID, "ebi", bc.EBI, "error", err)
			return s2b.UpdateBearerResult{Cause: 64, PGWControlTEID: pgwControlTEID}
		}
	}
	return s2b.UpdateBearerResult{Cause: 16, PGWControlTEID: pgwControlTEID}
}

// ────────────────────────────────────────────────────────────────────────────
// Session cleanup
// ────────────────────────────────────────────────────────────────────────────

func cleanupSession(sess *session.Session, gtpuManager *gtpu.Manager, s2bClient *s2b.Client, log *slog.Logger, reason string, sendS2BDelete bool) {
	if sess == nil {
		return
	}
	sess.Lock()
	if sess.State == session.StateDeleted {
		sess.Unlock()
		return
	}
	_ = sess.Transition(session.StateCleaningUp)
	hasS2B := sess.S2B != nil
	var s2bCtx session.S2BContext
	if hasS2B {
		s2bCtx = *sess.S2B
	}
	sess.Unlock()

	// gtpuManager.RemoveSession takes sess and locks internally for its own
	// field accesses — do not hold sess.Lock() across this call.
	if hasS2B {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := gtpuManager.RemoveSession(ctx, sess); err != nil {
			log.Warn("GTP-U session remove failed", "session_id", sess.ID, "error", err)
		}
		cancel()
	}
	if sendS2BDelete && hasS2B && s2bCtx.PGWControlTEID != 0 && s2bCtx.EBI != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		if err := s2bClient.DeleteSession(ctx, s2bCtx.PGWControlIP, s2bCtx.PGWControlTEID, s2bCtx.LocalControlTEID, s2bCtx.LocalUserTEID, s2bCtx.EBI); err != nil {
			log.Warn("S2b Delete Session failed", "session_id", sess.ID, "error", err)
		}
		cancel()
	}
	sess.Lock()
	_ = sess.Transition(session.StateDeleted)
	sess.Unlock()
	log.Info("session cleaned up", "session_id", sess.ID, "reason", reason)
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────

func allocateBearerTEID(ctx context.Context, gtpuManager *gtpu.Manager, sessionID string, b gtpu.Bearer) (uint32, error) {
	var lastErr error
	for i := 0; i < 8; i++ {
		teid, err := gtpu.AllocateTEID()
		if err != nil {
			return 0, err
		}
		b.LocalRXTEID = teid
		if err := gtpuManager.AddBearer(ctx, sessionID, b); err != nil {
			lastErr = err
			continue
		}
		return teid, nil
	}
	return 0, lastErr
}

func allocateDedicatedEBI(gtpuManager *gtpu.Manager, sessionID string, defaultEBI uint8) (uint8, error) {
	for ebi := uint8(6); ebi <= 15; ebi++ {
		if ebi == defaultEBI {
			continue
		}
		if !gtpuManager.HasBearer(sessionID, ebi) {
			return ebi, nil
		}
	}
	return 0, fmt.Errorf("no dedicated EBI available")
}

func buildInfo() string {
	return fmt.Sprintf("VectorCore ePDG %s\nbuild_date: %s\ngo: %s\n",
		version, buildDate, runtime.Version())
}
