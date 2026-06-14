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
)

// ────────────────────────────────────────────────────────────────────────────
// DH groups
// ────────────────────────────────────────────────────────────────────────────

type dhGroup struct {
	id        uint16
	prime     *big.Int
	generator *big.Int
	byteLen   int
}

func (g *dhGroup) TransformID() uint16 { return g.id }
func (g *dhGroup) ByteLen() int        { return g.byteLen }

func (g *dhGroup) GeneratePrivateKey() (*big.Int, error) {
	max := new(big.Int).Sub(g.prime, big.NewInt(2))
	priv, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Add(priv, big.NewInt(2)), nil
}

func (g *dhGroup) PublicKey(priv *big.Int) []byte {
	pub := new(big.Int).Exp(g.generator, priv, g.prime).Bytes()
	out := make([]byte, g.byteLen)
	copy(out[g.byteLen-len(pub):], pub)
	return out
}

func (g *dhGroup) SharedKey(priv *big.Int, peerPubBytes []byte) ([]byte, error) {
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

// RFC 3526 Group 14 (2048-bit MODP).
var dhGroup14 = &dhGroup{
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
var dhGroup15 = &dhGroup{
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

func dhGroupByID(id uint16) *dhGroup {
	switch id {
	case message.DH_2048_BIT_MODP:
		return dhGroup14
	case message.DH_3072_BIT_MODP:
		return dhGroup15
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
// Encryption (AES-CBC)
// ────────────────────────────────────────────────────────────────────────────

type encrAlg struct {
	id      uint16
	keyBits int
}

func (e *encrAlg) TransformID() uint16 { return e.id }
func (e *encrAlg) KeyLen() int         { return e.keyBits / 8 }
func (e *encrAlg) BlockSize() int      { return aes.BlockSize }

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
)

func encrByIDAndKeyBits(id uint16, keyBits int) *encrAlg {
	if id != message.ENCR_AES_CBC {
		return nil
	}
	switch keyBits {
	case 128:
		return encrAesCbc128
	case 256:
		return encrAesCbc256
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// IKE SA keying material
// ────────────────────────────────────────────────────────────────────────────

// ikeSAKey holds negotiated algorithms and all IKE SA keying material.
type ikeSAKey struct {
	// Negotiated algorithms
	dh    *dhGroup
	encr  *encrAlg
	integ *integAlg
	prf   *prfAlg

	// Derived keys
	SK_d  []byte
	SK_ai []byte
	SK_ar []byte
	SK_ei []byte
	SK_er []byte
	SK_pi []byte
	SK_pr []byte
}

// deriveKeys computes SKEYSEED and all SK_* keys per RFC 7296 §2.14.
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

	totalLen := prf.KeyLen() + // SK_d
		k.integ.KeyLen()*2 + // SK_ai + SK_ar
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
	k.SK_ai = take(k.integ.KeyLen())
	k.SK_ar = take(k.integ.KeyLen())
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
