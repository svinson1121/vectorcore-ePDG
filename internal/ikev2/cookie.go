package ikev2

// RFC 7296 §2.6 COOKIE challenge: once the responder is under load, it can
// require the initiator to echo back a stateless, unforgeable cookie before
// it will perform any DH computation or allocate an IKE SA. An attacker
// spoofing the source address never receives the cookie and can't complete
// the challenge; a real flood is limited to the cost of one HMAC per packet
// (no DH, no key derivation, no allocation) until cookies are presented.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// cookieSecretLifetime bounds how long a cookie-signing secret is reused.
// Cookies are anti-DoS padding, not a security/authentication boundary, so
// this only needs to be short enough to limit the value of a leaked secret.
const cookieSecretLifetime = 5 * time.Minute

// cookieState issues and verifies cookies without retaining any
// per-initiator state: both operations recompute the same HMAC from the
// initiator's SPI and source address plus a rotating secret.
type cookieState struct {
	mu         sync.Mutex
	secret     [32]byte
	prevSecret [32]byte
	rotatedAt  time.Time
}

func newCookieState() *cookieState {
	c := &cookieState{rotatedAt: time.Now()}
	if _, err := rand.Read(c.secret[:]); err != nil {
		panic("ikev2: cookie secret generation failed: " + err.Error())
	}
	c.prevSecret = c.secret
	return c
}

// secrets returns the current and previous signing secret, rotating the
// current one if it's older than cookieSecretLifetime. Keeping the previous
// secret around means a cookie issued just before a rotation still verifies.
func (c *cookieState) secrets() (cur, prev [32]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.rotatedAt) > cookieSecretLifetime {
		c.prevSecret = c.secret
		if _, err := rand.Read(c.secret[:]); err == nil {
			c.rotatedAt = time.Now()
		}
	}
	return c.secret, c.prevSecret
}

// issue computes the cookie value for an IKE_SA_INIT request from the
// initiator's SPI and source address. Deliberately excludes the nonce: RFC
// 7296 permits the initiator to pick a new nonce on the cookie-retry, and
// binding to it would reject legitimate retries that do so.
func (c *cookieState) issue(spiI uint64, remote *net.UDPAddr) []byte {
	cur, _ := c.secrets()
	return cookieHMAC(cur, spiI, remote)
}

// verify reports whether received matches a cookie this state would have
// issued for spiI/remote, against both the current and previous secret.
func (c *cookieState) verify(received []byte, spiI uint64, remote *net.UDPAddr) bool {
	if len(received) == 0 {
		return false
	}
	cur, prev := c.secrets()
	return hmac.Equal(received, cookieHMAC(cur, spiI, remote)) ||
		hmac.Equal(received, cookieHMAC(prev, spiI, remote))
}

func cookieHMAC(secret [32]byte, spiI uint64, remote *net.UDPAddr) []byte {
	h := hmac.New(sha256.New, secret[:])
	var spiBuf [8]byte
	binary.BigEndian.PutUint64(spiBuf[:], spiI)
	h.Write(spiBuf[:])
	h.Write(natAddrBytes(remote.IP))
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(remote.Port))
	h.Write(portBuf[:])
	return h.Sum(nil)
}
