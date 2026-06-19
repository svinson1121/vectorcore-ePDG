package ikev2

// IKEv2 crypto layer.
//
// free5gc/ike/message handles packet parsing/encoding.
// We own all crypto because their security interfaces use unexported methods
// that cannot be implemented outside the package.
//
// Supported transforms (from production swanctl config):
//   IKE: aes256-sha256-prfsha256-modp2048/3072
//        aes256-sha512-prfsha512-modp2048/3072
//        aes128-sha1-prfsha1-modp2048
//   ESP: same enc+integ, with PFS DH

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math/big"

	"github.com/free5gc/ike/message"
)

// Transform IDs not defined in free5gc/ike/message/types.go.
const (
	prfHmacSha2512      uint16 = 7
	authHmacSha2512_256 uint16 = 14
	dh256RandomECP      uint16 = 19 // IANA Group 19 (P-256), RFC 5114/5903
	dh384RandomECP      uint16 = 20 // IANA Group 20 (P-384), RFC 5114/5903
	encrAESGCM16        uint16 = 20 // ENCR_AES_GCM_16, RFC 5282 (16-octet ICV)
)

// ────────────────────────────────────────────────────────────────────────────
// DH groups
// ────────────────────────────────────────────────────────────────────────────

// dhGroup abstracts a Diffie-Hellman key exchange method (MODP or ECDH).
// Private keys are opaque (any) since MODP uses *big.Int and ECDH uses
// *ecdh.PrivateKey; callers only ever pass a value back to the same group
// that produced it, so the concrete type never needs to leak out.
type dhGroup interface {
	TransformID() uint16
	ByteLen() int
	GeneratePrivateKey() (any, error)
	PublicKey(priv any) []byte
	SharedKey(priv any, peerPubBytes []byte) ([]byte, error)
}

// modpGroup implements dhGroup for RFC 3526 MODP groups.
type modpGroup struct {
	id        uint16
	prime     *big.Int
	generator *big.Int
	byteLen   int
}

func (g *modpGroup) TransformID() uint16 { return g.id }
func (g *modpGroup) ByteLen() int        { return g.byteLen }

func (g *modpGroup) GeneratePrivateKey() (any, error) {
	max := new(big.Int).Sub(g.prime, big.NewInt(2))
	priv, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(priv, big.NewInt(2)), nil
}

func (g *modpGroup) PublicKey(privAny any) []byte {
	priv := privAny.(*big.Int)
	pub := new(big.Int).Exp(g.generator, priv, g.prime).Bytes()
	out := make([]byte, g.byteLen)
	copy(out[g.byteLen-len(pub):], pub)
	return out
}

func (g *modpGroup) SharedKey(privAny any, peerPubBytes []byte) ([]byte, error) {
	priv := privAny.(*big.Int)
	peer := new(big.Int).SetBytes(peerPubBytes)
	one := big.NewInt(1)
	pMinus1 := new(big.Int).Sub(g.prime, one)
	if peer.Cmp(one) <= 0 || peer.Cmp(pMinus1) >= 0 {
		return nil, fmt.Errorf("invalid DH public value")
	}
	shared := new(big.Int).Exp(peer, priv, g.prime).Bytes()
	out := make([]byte, g.byteLen)
	copy(out[g.byteLen-len(shared):], shared)
	return out, nil
}

// ecdhGroup implements dhGroup for NIST curve ECDH groups (RFC 5903).
// IKEv2 KE payload data for these groups is the raw, uncompressed X9.62
// point with the leading 0x04 tag stripped (RFC 5903 §7): X | Y, each
// byteLen bytes — not Go's ecdh.PublicKey.Bytes() encoding, which keeps the
// 0x04 tag. PublicKey/SharedKey below convert between the two forms.
type ecdhGroup struct {
	id      uint16
	curve   ecdh.Curve
	byteLen int // length of X (or Y) alone, e.g. 32 for P-256, 48 for P-384
}

func (g *ecdhGroup) TransformID() uint16 { return g.id }
func (g *ecdhGroup) ByteLen() int        { return 2 * g.byteLen }

func (g *ecdhGroup) GeneratePrivateKey() (any, error) {
	return g.curve.GenerateKey(rand.Reader)
}

func (g *ecdhGroup) PublicKey(privAny any) []byte {
	priv := privAny.(*ecdh.PrivateKey)
	// priv.PublicKey().Bytes() is 0x04 || X || Y; IKEv2 wants X || Y only.
	return priv.PublicKey().Bytes()[1:]
}

func (g *ecdhGroup) SharedKey(privAny any, peerPubBytes []byte) ([]byte, error) {
	if len(peerPubBytes) != 2*g.byteLen {
		return nil, fmt.Errorf("invalid ECDH public value length %d", len(peerPubBytes))
	}
	priv := privAny.(*ecdh.PrivateKey)
	uncompressed := append([]byte{0x04}, peerPubBytes...)
	peerPub, err := g.curve.NewPublicKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDH public value: %w", err)
	}
	return priv.ECDH(peerPub)
}

var ecdh256Group = &ecdhGroup{id: dh256RandomECP, curve: ecdh.P256(), byteLen: 32}
var ecdh384Group = &ecdhGroup{id: dh384RandomECP, curve: ecdh.P384(), byteLen: 48}

// RFC 3526 Group 14 (2048-bit MODP).
var dhGroup14 = &modpGroup{
	id: message.DH_2048_BIT_MODP,
	prime: mustParseBig("FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE45B3DC2007CB8A163BF05" +
		"98DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB" +
		"9ED529077096966D670C354E4ABC9804" +
		"F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28F" +
		"B5C55DF06F4C52C9DE2BCBF695581718" +
		"3995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"),
	generator: big.NewInt(2),
	byteLen:   256,
}

// RFC 3526 Group 15 (3072-bit MODP).
var dhGroup15 = &modpGroup{
	id: message.DH_3072_BIT_MODP,
	prime: mustParseBig("FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE45B3DC2007CB8A163BF05" +
		"98DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB" +
		"9ED529077096966D670C354E4ABC9804" +
		"F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28F" +
		"B5C55DF06F4C52C9DE2BCBF695581718" +
		"3995497CEA956AE515D2261898FA0510" +
		"15728E5A8AAAC42DAD33170D04507A33" +
		"A85521ABDF1CBA64ECFB850458DBEF0A" +
		"8AEA71575D060C7DB3970F85A6E1E4C7" +
		"ABF5AE8CDB0933D71E8C94E04A25619D" +
		"CEE3D2261AD2EE6BF12FFA06D98A0864" +
		"D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E2" +
		"08E24FA074E5AB3143DB5BFCE0FD108E" +
		"4B82D120A93AD2CAFFFFFFFFFFFFFFFF"),
	generator: big.NewInt(2),
	byteLen:   384,
}

func dhGroupByID(id uint16) dhGroup {
	switch id {
	case message.DH_2048_BIT_MODP:
		return dhGroup14
	case message.DH_3072_BIT_MODP:
		return dhGroup15
	case dh256RandomECP:
		return ecdh256Group
	case dh384RandomECP:
		return ecdh384Group
	}
	return nil
}

func mustParseBig(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("ikev2: bad prime constant")
	}
	return n
}

// ────────────────────────────────────────────────────────────────────────────
// PRF
// ────────────────────────────────────────────────────────────────────────────

type prfAlg struct {
	id        uint16
	keyLen    int
	outputLen int
	newHash   func(key []byte) hash.Hash
}

func (p *prfAlg) TransformID() uint16 { return p.id }
func (p *prfAlg) KeyLen() int         { return p.keyLen }
func (p *prfAlg) OutputLen() int      { return p.outputLen }
func (p *prfAlg) New(key []byte) hash.Hash {
	return p.newHash(key)
}

var (
	prfSha1 = &prfAlg{
		id: message.PRF_HMAC_SHA1, keyLen: 20, outputLen: 20,
		newHash: func(key []byte) hash.Hash { return hmac.New(sha1.New, key) },
	}
	prfSha256 = &prfAlg{
		id: message.PRF_HMAC_SHA2_256, keyLen: 32, outputLen: 32,
		newHash: func(key []byte) hash.Hash { return hmac.New(sha256.New, key) },
	}
	prfSha512 = &prfAlg{
		id: prfHmacSha2512, keyLen: 64, outputLen: 64,
		newHash: func(key []byte) hash.Hash { return hmac.New(sha512.New, key) },
	}
)

func prfByID(id uint16) *prfAlg {
	switch id {
	case message.PRF_HMAC_SHA1:
		return prfSha1
	case message.PRF_HMAC_SHA2_256:
		return prfSha256
	case prfHmacSha2512:
		return prfSha512
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Integrity / INTEG
// ────────────────────────────────────────────────────────────────────────────

type integAlg struct {
	id        uint16
	keyLen    int
	outputLen int // truncated output written to packet
	newHash   func(key []byte) hash.Hash
}

func (a *integAlg) TransformID() uint16 { return a.id }
func (a *integAlg) KeyLen() int         { return a.keyLen }
func (a *integAlg) OutputLen() int      { return a.outputLen }
func (a *integAlg) New(key []byte) hash.Hash {
	return a.newHash(key)
}

var (
	integSha1_96 = &integAlg{
		id: message.AUTH_HMAC_SHA1_96, keyLen: 20, outputLen: 12,
		newHash: func(key []byte) hash.Hash { return hmac.New(sha1.New, key) },
	}
	integSha256_128 = &integAlg{
		id: message.AUTH_HMAC_SHA2_256_128, keyLen: 32, outputLen: 16,
		newHash: func(key []byte) hash.Hash { return hmac.New(sha256.New, key) },
	}
	integSha512_256 = &integAlg{
		id: authHmacSha2512_256, keyLen: 64, outputLen: 32,
		newHash: func(key []byte) hash.Hash { return hmac.New(sha512.New, key) },
	}
)

func integByID(id uint16) *integAlg {
	switch id {
	case message.AUTH_HMAC_SHA1_96:
		return integSha1_96
	case message.AUTH_HMAC_SHA2_256_128:
		return integSha256_128
	case authHmacSha2512_256:
		return integSha512_256
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// Encryption (AES-CBC, AES-GCM)
// ────────────────────────────────────────────────────────────────────────────

// encrAlg describes a negotiable encryption transform. keyBits is the AES
// key size carried in the wire Key Length attribute (128/256) — it must
// stay the raw AES key size, not include saltLen, or proposal attribute
// matching in hasEncr/buildESPSAResponse would offer/expect the wrong value.
// saltLen is the additional salt appended to the derived key material for
// AEAD ciphers (4 bytes for GCM per RFC 4106 §8.1); zero for CBC. ESP
// encryption itself is delegated to the kernel via XFRM (see internal/xfrm),
// so Encrypt/Decrypt below are only ever used for IKE SA (CBC) traffic.
type encrAlg struct {
	id      uint16
	keyBits int
	saltLen int
}

func (e *encrAlg) TransformID() uint16 { return e.id }
func (e *encrAlg) KeyLen() int         { return e.keyBits/8 + e.saltLen }
func (e *encrAlg) BlockSize() int      { return aes.BlockSize }
func (e *encrAlg) IsAEAD() bool        { return e.saltLen > 0 }

func (e *encrAlg) Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// PKCS7 pad
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := make([]byte, len(plaintext)+padLen)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded)-1; i++ {
		padded[i] = 0
	}
	padded[len(padded)-1] = byte(padLen - 1) // RFC 7296 §3.14: pad length = padLen-1

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize+len(padded))
	copy(out, iv)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[aes.BlockSize:], padded)
	return out, nil
}

func (e *encrAlg) Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ikev2: invalid ciphertext length %d", len(ciphertext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := ciphertext[:aes.BlockSize]
	plain := make([]byte, len(ciphertext)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext[aes.BlockSize:])
	if len(plain) == 0 {
		return nil, fmt.Errorf("ikev2: empty plaintext after decrypt")
	}
	padLen := int(plain[len(plain)-1]) + 1
	if padLen > len(plain) {
		return nil, fmt.Errorf("ikev2: bad pad length %d", padLen)
	}
	return plain[:len(plain)-padLen], nil
}

var (
	encrAesCbc128 = &encrAlg{id: message.ENCR_AES_CBC, keyBits: 128}
	encrAesCbc256 = &encrAlg{id: message.ENCR_AES_CBC, keyBits: 256}

	// AES-GCM with a 16-octet ICV (RFC 5282 / IANA transform ID 20). Currently
	// ESP-only (docs/ipsec-gaps.md Gap 1) — the kernel performs the AEAD
	// Seal/Open via XFRM, so these are never passed to encrAlg.Encrypt/Decrypt.
	encrAesGcm16_128 = &encrAlg{id: encrAESGCM16, keyBits: 128, saltLen: 4}
	encrAesGcm16_256 = &encrAlg{id: encrAESGCM16, keyBits: 256, saltLen: 4}
)

func encrByIDAndKeyBits(id uint16, keyBits int) *encrAlg {
	switch id {
	case message.ENCR_AES_CBC:
		switch keyBits {
		case 128:
			return encrAesCbc128
		case 256:
			return encrAesCbc256
		}
	case encrAESGCM16:
		switch keyBits {
		case 128:
			return encrAesGcm16_128
		case 256:
			return encrAesGcm16_256
		}
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// IKE SA keying material
// ────────────────────────────────────────────────────────────────────────────

// ikeSAKey holds negotiated algorithms and all IKE SA keying material.
// integ is nil for AEAD ciphers (AES-GCM) — see negotiatedProposal.
type ikeSAKey struct {
	// Negotiated algorithms
	dh    dhGroup
	encr  *encrAlg
	integ *integAlg
	prf   *prfAlg

	// Derived keys. SK_ai/SK_ar are zero-length (not nil) when integ == nil.
	SK_d  []byte
	SK_ai []byte
	SK_ar []byte
	SK_ei []byte
	SK_er []byte
	SK_pi []byte
	SK_pr []byte
}

// integKeyLen returns 0 for AEAD (integ == nil) instead of nil-dereferencing.
func (k *ikeSAKey) integKeyLen() int {
	if k.integ == nil {
		return 0
	}
	return k.integ.KeyLen()
}

// deriveKeys computes SKEYSEED and all SK_* keys per RFC 7296 §2.14. For
// AEAD ciphers, SK_ai/SK_ar are taken with length 0 per RFC 5282 §3.1 ("the
// length of SK_ai and SK_ar MUST be zero for any transform which uses an
// integrated encryption algorithm") — take(0) is a no-op on the KEYMAT
// cursor, so this produces the same SK_ei/er/pi/pr as if ai/ar were omitted
// from the derivation entirely.
// concatenatedNonce = Ni | Nr
// dhSharedKey = g^ir
func (k *ikeSAKey) deriveKeys(concatenatedNonce, dhSharedKey []byte, spiI, spiR uint64) error {
	prf := k.prf

	// SKEYSEED = prf(Ni | Nr, g^ir)
	h := prf.New(concatenatedNonce)
	h.Write(dhSharedKey)
	skeyseed := h.Sum(nil)

	// seed = Ni | Nr | SPI_I | SPI_R
	seed := make([]byte, len(concatenatedNonce)+16)
	copy(seed, concatenatedNonce)
	binary.BigEndian.PutUint64(seed[len(concatenatedNonce):], spiI)
	binary.BigEndian.PutUint64(seed[len(concatenatedNonce)+8:], spiR)

	integKeyLen := k.integKeyLen()
	totalLen := prf.KeyLen() + // SK_d
		integKeyLen*2 + // SK_ai + SK_ar
		k.encr.KeyLen()*2 + // SK_ei + SK_er
		prf.KeyLen()*2 // SK_pi + SK_pr

	keymat := prfPlus(prf.New(skeyseed), seed, totalLen)

	off := 0
	take := func(n int) []byte {
		b := make([]byte, n)
		copy(b, keymat[off:off+n])
		off += n
		return b
	}
	k.SK_d = take(prf.KeyLen())
	k.SK_ai = take(integKeyLen)
	k.SK_ar = take(integKeyLen)
	k.SK_ei = take(k.encr.KeyLen())
	k.SK_er = take(k.encr.KeyLen())
	k.SK_pi = take(prf.KeyLen())
	k.SK_pr = take(prf.KeyLen())
	return nil
}

// prfPlus implements the PRF+ construction from RFC 7296 §2.13.
func prfPlus(h hash.Hash, seed []byte, length int) []byte {
	var out, prev []byte
	for i := 1; len(out) < length; i++ {
		h.Reset()
		h.Write(prev)
		h.Write(seed)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// ────────────────────────────────────────────────────────────────────────────
// SK payload encrypt / decrypt (RFC 7296 §3.14)
// ────────────────────────────────────────────────────────────────────────────

// encryptSK encrypts inner payloads into an SK-wrapped IKE message ready to send.
// ikeMsgHeader is the 28-byte IKE fixed header with Length already set to final.
// innerNextPayload is the payload type of the first inner payload (written into the
// SK generic header before the HMAC is computed, so the HMAC covers it correctly).
func encryptSK(saKey *ikeSAKey, innerNextPayload uint8, plainPayloads []byte, ikeMsgHeader []byte) ([]byte, error) {
	if saKey.encr.IsAEAD() {
		return encryptSKAEAD(saKey, innerNextPayload, plainPayloads, ikeMsgHeader)
	}

	ciphertext, err := saKey.encr.Encrypt(saKey.SK_er, plainPayloads)
	if err != nil {
		return nil, fmt.Errorf("ikev2 encrypt: %w", err)
	}

	integLen := saKey.integ.OutputLen()
	skPayloadLen := 4 + len(ciphertext) + integLen
	out := make([]byte, len(ikeMsgHeader)+skPayloadLen)
	copy(out, ikeMsgHeader)
	// SK payload generic header: inner next-payload, critical=0, length.
	out[len(ikeMsgHeader)+0] = innerNextPayload
	out[len(ikeMsgHeader)+1] = 0
	binary.BigEndian.PutUint16(out[len(ikeMsgHeader)+2:], uint16(skPayloadLen))
	copy(out[len(ikeMsgHeader)+4:], ciphertext)

	// HMAC over entire message except the trailing checksum bytes.
	mac := saKey.integ.New(saKey.SK_ar)
	mac.Write(out[:len(out)-integLen])
	copy(out[len(out)-integLen:], mac.Sum(nil)[:integLen])
	return out, nil
}

// decryptSK verifies integrity and decrypts the SK payload of a received IKE message.
// Returns the inner next-payload type (from the SK generic header) and plaintext bytes.
// Incoming messages use SK_ai for integrity and SK_ei for encryption (initiator keys).
func decryptSK(saKey *ikeSAKey, msg []byte) (innerNextPayload uint8, plain []byte, err error) {
	if saKey.encr.IsAEAD() {
		return decryptSKAEAD(saKey, msg)
	}

	integLen := saKey.integ.OutputLen()
	if len(msg) < 28+4+integLen {
		return 0, nil, fmt.Errorf("ikev2 decrypt: message too short")
	}

	// Verify integrity over message minus trailing checksum.
	mac := saKey.integ.New(saKey.SK_ai)
	mac.Write(msg[:len(msg)-integLen])
	if !hmac.Equal(mac.Sum(nil)[:integLen], msg[len(msg)-integLen:]) {
		return 0, nil, fmt.Errorf("ikev2 decrypt: integrity check failed")
	}

	// SK payload starts at byte 28; its generic header is 4 bytes.
	// Byte 28 = inner next-payload type.
	innerNextPayload = msg[28]
	skPayload := msg[28:]
	ciphertext := skPayload[4 : len(skPayload)-integLen]
	plain, err = saKey.encr.Decrypt(saKey.SK_ei, ciphertext)
	return innerNextPayload, plain, err
}

// ────────────────────────────────────────────────────────────────────────────
// SK payload encrypt / decrypt — combined-mode / AEAD ciphers (RFC 5282 §3)
// ────────────────────────────────────────────────────────────────────────────
//
// Wire format differs from the CBC+HMAC format above: instead of a
// block-size IV followed by padded ciphertext and a separately-computed
// trailing HMAC, the Encrypted payload carries an explicit IV (here, 8
// bytes — enough to make the 12-byte GCM nonce unique per message when
// combined with the 4-byte salt baked into the key) immediately followed by
// ciphertext+authentication-tag as one unit (what Go's cipher.AEAD.Seal
// produces directly). There is no padding (GCM needs none) and no separate
// integrity key/algorithm — SK_ai/SK_ar are zero-length and unused.
//
// The Additional Authenticated Data (AAD) is the IKE header plus the SK
// payload's own generic header (next-payload, reserved, length) — i.e.
// everything on the wire before the explicit IV (RFC 5282 §3.1).

func aeadCipher(key []byte, saltLen int) (gcm cipher.AEAD, salt []byte, err error) {
	if len(key) <= saltLen {
		return nil, nil, fmt.Errorf("ikev2 AEAD: key too short for salt length %d", saltLen)
	}
	aesKey, salt := key[:len(key)-saltLen], key[len(key)-saltLen:]
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, err
	}
	gcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return gcm, salt, nil
}

func encryptSKAEAD(saKey *ikeSAKey, innerNextPayload uint8, plainPayloads, ikeMsgHeader []byte) ([]byte, error) {
	gcm, salt, err := aeadCipher(saKey.SK_er, saKey.encr.saltLen)
	if err != nil {
		return nil, fmt.Errorf("ikev2 encrypt (AEAD): %w", err)
	}

	explicitIV := make([]byte, gcm.NonceSize()-len(salt))
	if _, err := io.ReadFull(rand.Reader, explicitIV); err != nil {
		return nil, fmt.Errorf("ikev2 encrypt (AEAD): %w", err)
	}
	nonce := append(append([]byte{}, salt...), explicitIV...)

	skPayloadLen := 4 + len(explicitIV) + len(plainPayloads) + gcm.Overhead()
	out := make([]byte, len(ikeMsgHeader)+skPayloadLen)
	copy(out, ikeMsgHeader)
	hdrOff := len(ikeMsgHeader)
	out[hdrOff+0] = innerNextPayload
	out[hdrOff+1] = 0
	binary.BigEndian.PutUint16(out[hdrOff+2:], uint16(skPayloadLen))
	copy(out[hdrOff+4:], explicitIV)

	aad := out[:hdrOff+4] // ikeMsgHeader || SK generic header, before the IV
	ciphertext := gcm.Seal(nil, nonce, plainPayloads, aad)
	copy(out[hdrOff+4+len(explicitIV):], ciphertext)
	return out, nil
}

func decryptSKAEAD(saKey *ikeSAKey, msg []byte) (innerNextPayload uint8, plain []byte, err error) {
	gcm, salt, err := aeadCipher(saKey.SK_ei, saKey.encr.saltLen)
	if err != nil {
		return 0, nil, fmt.Errorf("ikev2 decrypt (AEAD): %w", err)
	}

	explicitIVLen := gcm.NonceSize() - len(salt)
	const hdrLen = 28 + 4 // IKE fixed header + SK generic header
	if len(msg) < hdrLen+explicitIVLen+gcm.Overhead() {
		return 0, nil, fmt.Errorf("ikev2 decrypt (AEAD): message too short")
	}

	innerNextPayload = msg[28]
	explicitIV := msg[hdrLen : hdrLen+explicitIVLen]
	nonce := append(append([]byte{}, salt...), explicitIV...)
	aad := msg[:hdrLen]
	ciphertext := msg[hdrLen+explicitIVLen:]

	plain, err = gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return 0, nil, fmt.Errorf("ikev2 decrypt (AEAD): integrity check failed: %w", err)
	}
	return innerNextPayload, plain, nil
}
