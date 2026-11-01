package dynv

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// MaxCT is the longest accepted blob ciphertext, in characters (§4.3 step 1).
const MaxCT = 349_589

// --- §2 encodings ---------------------------------------------------------

// B64u encodes base64url without padding.
func B64u(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

var errB64 = errors.New("invalid base64url")

// B64uDecode decodes strict base64url (§2): no padding, no other characters,
// no length ≡ 1 (mod 4), canonical trailing bits.
func B64uDecode(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if !b64char(s[i]) {
			return nil, errB64
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || B64u(raw) != s {
		return nil, errB64
	}
	return raw, nil
}

func b64char(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// IsID reports whether s is a valid id: exactly 16 characters of [A-Za-z0-9_-] (§2).
func IsID(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !b64char(s[i]) {
			return false
		}
	}
	return true
}

func isIDValue(x any) bool {
	s, ok := x.(string)
	return ok && IsID(s)
}

// --- §3 tokens ------------------------------------------------------------

// Token is a parsed Dynv token. The secret never leaves the process and is
// never printed.
type Token struct {
	Kind   string // "pt", "mt" or "at"
	ID     string
	secret []byte
}

// ErrMalformedToken is returned by [ParseToken]; it never echoes the token.
var ErrMalformedToken = errors.New("dynv: malformed token")

// ParseToken parses `dynv_<kind>_<id>.<b64u(secret)>` (§3) after trimming
// surrounding whitespace.
func ParseToken(text string) (*Token, error) {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "dynv_") || len(t) < 5+3+16+1 || t[7] != '_' || t[24] != '.' {
		return nil, ErrMalformedToken
	}
	kind, id := t[5:7], t[8:24]
	if kind != "pt" && kind != "mt" && kind != "at" || !IsID(id) {
		return nil, ErrMalformedToken
	}
	secret, err := B64uDecode(t[25:])
	if err != nil || len(secret) != 32 {
		return nil, ErrMalformedToken
	}
	return &Token{Kind: kind, ID: id, secret: secret}, nil
}

// String never includes the secret.
func (t *Token) String() string { return fmt.Sprintf("dynv_%s_%s.…", t.Kind, t.ID) }

// Secret returns a copy of the 32-byte secret (for tests).
func (t *Token) Secret() []byte { return append([]byte(nil), t.secret...) }

func (t *Token) derive(purpose string) []byte {
	out := make([]byte, 32)
	r := hkdf.New(sha256.New, t.secret, []byte("dynv/v1"), []byte(purpose+"|"+t.Kind+"|"+t.ID))
	if _, err := io.ReadFull(r, out); err != nil {
		panic(err) // 32 bytes of HKDF-SHA256 cannot fail
	}
	return out
}

// AuthKey is sent to the server (§3).
func (t *Token) AuthKey() []byte { return t.derive("auth") }

// WrapKey opens the token's envelope; it never leaves the client (§3).
func (t *Token) WrapKey() []byte { return t.derive("wrap") }

// Verifier is what the server stores: hex(SHA-256(auth key)).
func (t *Token) Verifier() string {
	h := sha256.Sum256(t.AuthKey())
	return hex.EncodeToString(h[:])
}

// Authorization is the `Authorization` header value.
func (t *Token) Authorization() string {
	return "Dynv " + t.Kind + "." + t.ID + "." + B64u(t.AuthKey())
}

// --- §4 primitives --------------------------------------------------------

// AAD builds `dynv/v1/<kind>|<part>|…` (§4.2), integers in decimal.
func AAD(kind string, parts ...any) string {
	var b strings.Builder
	b.WriteString("dynv/v1/")
	b.WriteString(kind)
	for _, p := range parts {
		b.WriteByte('|')
		switch v := p.(type) {
		case string:
			b.WriteString(v)
		case uint64:
			b.WriteString(strconv.FormatUint(v, 10))
		case int:
			b.WriteString(strconv.Itoa(v))
		case Number:
			b.WriteString(string(v))
		default:
			fmt.Fprint(&b, v)
		}
	}
	return b.String()
}

// ErrDecrypt is the single error of [AEADOpen] (§4.1: don't distinguish causes).
var ErrDecrypt = errors.New("decrypt")

// AEADOpen opens `b64u(nonce ‖ ciphertext ‖ tag)` with AES-256-GCM (§4.1).
func AEADOpen(key []byte, sealed string, aad string) ([]byte, error) {
	raw, err := B64uDecode(sealed)
	if err != nil || len(raw) < 28 || len(key) != 32 {
		return nil, ErrDecrypt
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := gcm.Open(nil, raw[:12], raw[12:], []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// Ed25519Verify verifies a pure Ed25519 signature (RFC 8032).
func Ed25519Verify(publicKey, sig, msg []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), msg, sig)
}

// PaddedLen is the plaintext length for a document of jsonLen bytes (§4.3).
func PaddedLen(jsonLen int) int { return (4 + jsonLen + 1023) / 1024 * 1024 }

// BlobHash is the §4.4 content hash of a SealedBlob, over its fields as
// transmitted. The blob must have passed the shape check.
func BlobHash(blob map[string]any) string {
	s := fmt.Sprintf("%s|%s|%s|%s|%s", blob["version"], blob["dek_gen"], blob["signer"], blob["ct"], blob["sig"])
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// SVEntry is one delivered group for the watch fingerprint.
type SVEntry struct {
	GroupID                     string
	Version, DekGen, ProcessGen uint64
}

// SVFingerprint is the §4.4 watch fingerprint.
func SVFingerprint(entries []SVEntry) string {
	if len(entries) == 0 {
		return ""
	}
	e := append([]SVEntry(nil), entries...)
	sort.Slice(e, func(i, j int) bool {
		a, b := e[i], e[j]
		if a.GroupID != b.GroupID {
			return a.GroupID < b.GroupID
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		if a.DekGen != b.DekGen {
			return a.DekGen < b.DekGen
		}
		return a.ProcessGen < b.ProcessGen
	})
	var b strings.Builder
	for _, x := range e {
		fmt.Fprintf(&b, "%s:%d:%d:%d;", x.GroupID, x.Version, x.DekGen, x.ProcessGen)
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

// svOf fingerprints `shared` as received (§4.4, §8), skipping entries that
// don't have the fields.
func svOf(shared any) string {
	arr, _ := shared.([]any)
	var entries []SVEntry
	for _, x := range arr {
		e, _ := x.(map[string]any)
		blob, _ := e["blob"].(map[string]any)
		gid, ok1 := e["group_id"].(string)
		v, ok2 := Int(blob["version"])
		d, ok3 := Int(blob["dek_gen"])
		p, ok4 := Int(e["process_gen"])
		if ok1 && ok2 && ok3 && ok4 {
			entries = append(entries, SVEntry{gid, v, d, p})
		}
	}
	return SVFingerprint(entries)
}

// blobShapeOK is the §5 shape check: integer version/dek_gen, string ct/sig/signer.
func blobShapeOK(x any) (map[string]any, bool) {
	b, ok := x.(map[string]any)
	if !ok {
		return nil, false
	}
	if _, ok := Int(b["version"]); !ok {
		return nil, false
	}
	if _, ok := Int(b["dek_gen"]); !ok {
		return nil, false
	}
	for _, f := range []string{"ct", "sig", "signer"} {
		if _, ok := b[f].(string); !ok {
			return nil, false
		}
	}
	return b, true
}

var errBlob = errors.New("blob")

// BlobOpenRaw is §4.3 steps 1–5: verify, then decrypt, then unpad. It returns
// the document JSON bytes. The blob must have passed the shape check.
func BlobOpenRaw(blob map[string]any, dek []byte, signers []string, aad string) ([]byte, error) {
	ct, _ := blob["ct"].(string)
	signer, _ := blob["signer"].(string)
	sigText, _ := blob["sig"].(string)
	if len(ct) > MaxCT {
		return nil, errBlob
	}
	trusted := false
	for _, s := range signers {
		if s == signer {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, errBlob
	}
	sig, err := B64uDecode(sigText)
	if err != nil {
		return nil, errBlob
	}
	pub, err := B64uDecode(signer)
	if err != nil {
		return nil, errBlob
	}
	msg := make([]byte, 0, len(aad)+1+len(ct))
	msg = append(append(append(msg, aad...), '\n'), ct...)
	if !Ed25519Verify(pub, sig, msg) {
		return nil, errBlob
	}
	pt, err := AEADOpen(dek, ct, aad)
	if err != nil || len(pt) < 4 {
		return nil, errBlob
	}
	n := binary.BigEndian.Uint32(pt[:4])
	if uint64(n)+4 > uint64(len(pt)) {
		return nil, errBlob
	}
	return pt[4 : 4+n], nil
}
