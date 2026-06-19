package gtpu

import (
	"testing"
	"time"
)

// fakeBearerCounterReader implements bearerCounterReader for tests, keyed by
// TEID, without needing a live BPF map.
type fakeBearerCounterReader struct {
	counters map[uint32][2]uint64 // teid -> {packets, bytes}
}

func (f *fakeBearerCounterReader) BearerCounter(teid uint32) (packets, bytes uint64, ok bool) {
	v, ok := f.counters[teid]
	if !ok {
		return 0, 0, false
	}
	return v[0], v[1], true
}

func newSyncTestManager() (*Manager, *Session) {
	m := &Manager{
		sessionsByID:        make(map[string]*Session),
		bearersByLocalTEID:  make(map[uint32]*BearerRef),
		bearersByRemoteTEID: make(map[uint32]*BearerRef),
	}
	sess := &Session{
		ID: "sess-1",
		Bearers: map[uint8]*Bearer{
			5: {EBI: 5, LocalRXTEID: 10, RemoteTXTEID: 20},
		},
	}
	m.sessionsByID[sess.ID] = sess
	m.bearersByLocalTEID[10] = &BearerRef{SessionID: sess.ID, BearerEBI: 5}
	m.bearersByRemoteTEID[20] = &BearerRef{SessionID: sess.ID, BearerEBI: 5}
	return m, sess
}

func TestSyncBearerCounters(t *testing.T) {
	m, sess := newSyncTestManager()
	dl := &fakeBearerCounterReader{counters: map[uint32][2]uint64{10: {100, 5000}}}
	ul := &fakeBearerCounterReader{counters: map[uint32][2]uint64{20: {50, 2500}}}

	before := time.Now()
	m.syncBearerCounters(dl, ul)

	b := sess.Bearers[5]
	if b.Counters.DownlinkPackets != 100 || b.Counters.DownlinkBytes != 5000 {
		t.Fatalf("downlink counters = %+v", b.Counters)
	}
	if b.Counters.UplinkPackets != 50 || b.Counters.UplinkBytes != 2500 {
		t.Fatalf("uplink counters = %+v", b.Counters)
	}
	if b.Counters.LastDownlinkPacket.Before(before) || b.Counters.LastUplinkPacket.Before(before) {
		t.Fatalf("Last*Packet not advanced on first sync: %+v", b.Counters)
	}
}

func TestSyncBearerCountersLastPacketOnlyAdvancesOnNewTraffic(t *testing.T) {
	m, sess := newSyncTestManager()
	dl := &fakeBearerCounterReader{counters: map[uint32][2]uint64{10: {100, 5000}}}
	ul := &fakeBearerCounterReader{counters: map[uint32][2]uint64{20: {50, 2500}}}

	m.syncBearerCounters(dl, ul)
	b := sess.Bearers[5]
	midDL := b.Counters.LastDownlinkPacket
	midUL := b.Counters.LastUplinkPacket

	time.Sleep(time.Millisecond)
	m.syncBearerCounters(dl, ul) // same counts, no new traffic
	if !b.Counters.LastDownlinkPacket.Equal(midDL) {
		t.Fatalf("LastDownlinkPacket advanced with no new packets")
	}
	if !b.Counters.LastUplinkPacket.Equal(midUL) {
		t.Fatalf("LastUplinkPacket advanced with no new packets")
	}

	dl.counters[10] = [2]uint64{150, 7000}
	m.syncBearerCounters(dl, ul) // new downlink traffic only
	if !b.Counters.LastDownlinkPacket.After(midDL) {
		t.Fatalf("LastDownlinkPacket did not advance on new traffic")
	}
	if !b.Counters.LastUplinkPacket.Equal(midUL) {
		t.Fatalf("LastUplinkPacket advanced despite no new uplink traffic")
	}
}

func TestSyncBearerCountersNilReaders(t *testing.T) {
	m, _ := newSyncTestManager()
	m.syncBearerCounters(nil, nil) // must not panic when neither dataplane is attached
}

func TestSyncBearerCountersUnknownTEIDLeavesCountersUnchanged(t *testing.T) {
	m, sess := newSyncTestManager()
	dl := &fakeBearerCounterReader{counters: map[uint32][2]uint64{}} // no entry for TEID 10
	ul := &fakeBearerCounterReader{counters: map[uint32][2]uint64{}}

	m.syncBearerCounters(dl, ul)
	b := sess.Bearers[5]
	if b.Counters != (BearerCounters{}) {
		t.Fatalf("counters changed despite no BPF entry: %+v", b.Counters)
	}
}
