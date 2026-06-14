package session

import "sync"

type Manager struct {
	mu       sync.Mutex
	sessions map[string]*Session
	deleted  map[string]struct{}
}

func NewManager() *Manager {
	return &Manager{sessions: make(map[string]*Session), deleted: make(map[string]struct{})}
}

func (m *Manager) GetOrCreate(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess := m.sessions[id]; sess != nil {
		return sess
	}
	sess := New(id)
	m.sessions[id] = sess
	return sess
}

func (m *Manager) Get(id string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

func (m *Manager) FindByIKE(spiI, spiR uint64) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if spiI == 0 || spiR == 0 {
		return nil
	}
	for _, sess := range m.sessions {
		if sess.IkeSPII == spiI && sess.IkeSPIR == spiR {
			return sess
		}
	}
	return nil
}

func (m *Manager) FindByPAA(paa string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if paa == "" {
		return nil
	}
	for _, sess := range m.sessions {
		if sess.S2B != nil && sess.S2B.PAA == paa {
			return sess
		}
	}
	return nil
}

func (m *Manager) FindByIMSIAPN(imsi, apn string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if imsi == "" {
		return nil
	}
	for _, sess := range m.sessions {
		if sess.IMSI == imsi && (apn == "" || sess.APN == apn) {
			return sess
		}
	}
	return nil
}

func (m *Manager) FindSingleActiveByIMSIAPN(imsi, apn string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if imsi == "" {
		return nil, false
	}
	var found *Session
	for _, sess := range m.sessions {
		if sess.IMSI != imsi || (apn != "" && sess.APN != apn) || sess.State != StateActive {
			continue
		}
		if found != nil {
			return nil, false
		}
		found = sess
	}
	return found, found != nil
}

func (m *Manager) FindByLocalControlTEID(teid uint32) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if teid == 0 {
		return nil
	}
	for _, sess := range m.sessions {
		if sess.S2B != nil && sess.S2B.LocalControlTEID == teid {
			return sess
		}
	}
	return nil
}

func (m *Manager) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	if id != "" {
		m.deleted[id] = struct{}{}
	}
}

func (m *Manager) WasDeleted(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id == "" {
		return false
	}
	_, ok := m.deleted[id]
	return ok
}

func (m *Manager) Snapshot() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, sess := range m.sessions {
		out = append(out, sess)
	}
	return out
}
