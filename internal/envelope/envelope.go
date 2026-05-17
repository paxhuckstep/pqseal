// Package envelope implements the PQ-Sealed Envelope binary format defined in
// §4 of the challenge spec, plus the seal/verify/decrypt operations from §8.
//
// The envelope layout (all multi-byte integers big-endian) is:
//
//	magic         4   "PQS1"
//	flags         1   bit 0 = compressed, bits 1-7 reserved (must be zero)
//	kem_ct_len    4   uint32, must equal 1088
//	kem_ct        1088 ML-KEM-768 encapsulation ciphertext
//	nonce         12  AES-GCM nonce
//	policy_len    2   uint16
//	policy_blob   N   UTF-8 policy expression (AEAD additional data)
//	ct_len        4   uint32, AEAD output (ciphertext || tag) length
//	ciphertext    M   AES-256-GCM output
//	sig_len       2   uint16, must equal 3309
//	issuer_sig    3309 ML-DSA-65 signature over SHA-256 of all preceding bytes
package envelope

import (
	"encoding/binary"
	"errors"
)

// Fixed field sizes from the spec.
const (
	Magic         = "PQS1"
	MagicSize     = 4
	FlagsSize     = 1
	KEMCtLenSize  = 4
	KEMCtSize     = 1088 // ML-KEM-768 ciphertext
	NonceSize     = 12   // AES-GCM
	PolicyLenSize = 2
	CtLenSize     = 4
	SigLenSize    = 2
	SigSize       = 3309 // ML-DSA-65 signature

	// MaxEnvelopeSize is the §4 hard cap. Anything larger is rejected before
	// any length-prefixed allocation.
	MaxEnvelopeSize = 16 * 1024 * 1024
)

// Flags byte bit layout (§4.2).
const (
	FlagCompressed byte = 0x01
	flagReserved   byte = 0xFE // bits 1-7
)

// HKDF parameters (§8.1 step 2).
const HKDFInfo = "pqseal/v1/key"

// Sentinel errors. The HTTP layer maps these to the four user-visible error
// strings from §5.2; nothing else may leak out of this package.
var (
	ErrMalformed    = errors.New("malformed envelope")
	ErrAuthFailed   = errors.New("authentication failed")
	ErrPolicyDenied = errors.New("policy denied")
)

// Envelope is a parsed PQ-Sealed Envelope. Slice fields alias into the raw
// buffer passed to ParseEnvelope; callers must not mutate that buffer while
// the Envelope is in use.
type Envelope struct {
	Flags         byte
	KEMCiphertext []byte // KEMCtSize bytes
	Nonce         []byte // NonceSize bytes
	PolicyBlob    []byte // 0..65535 bytes
	Ciphertext    []byte // includes 16-byte GCM tag
	Signature     []byte // SigSize bytes

	// SigInputEnd is the offset into the raw buffer at which the signed
	// prefix ends (i.e. index immediately after Ciphertext). The signature
	// is computed over SHA-256(raw[:SigInputEnd]).
	SigInputEnd int
}

// ParseEnvelope validates and slices a raw envelope. Every length field is
// bounds-checked against the remaining buffer before any slice is taken, so
// a hostile length prefix cannot trigger an oversized allocation.
//
// On any structural failure ParseEnvelope returns ErrMalformed. No other
// error is ever returned from this function.
func ParseEnvelope(raw []byte) (*Envelope, error) {
	if len(raw) > MaxEnvelopeSize {
		return nil, ErrMalformed
	}
	r := &reader{buf: raw}

	magic, ok := r.read(MagicSize)
	if !ok || string(magic) != Magic {
		return nil, ErrMalformed
	}

	flags, ok := r.readByte()
	if !ok {
		return nil, ErrMalformed
	}
	if flags&flagReserved != 0 {
		return nil, ErrMalformed
	}

	kemCtLen, ok := r.readU32()
	if !ok || kemCtLen != KEMCtSize {
		return nil, ErrMalformed
	}
	kemCt, ok := r.read(int(kemCtLen))
	if !ok {
		return nil, ErrMalformed
	}

	nonce, ok := r.read(NonceSize)
	if !ok {
		return nil, ErrMalformed
	}

	policyLen, ok := r.readU16()
	if !ok {
		return nil, ErrMalformed
	}
	policyBlob, ok := r.read(int(policyLen))
	if !ok {
		return nil, ErrMalformed
	}

	ctLen, ok := r.readU32()
	if !ok {
		return nil, ErrMalformed
	}
	if ctLen > MaxEnvelopeSize {
		return nil, ErrMalformed
	}
	ciphertext, ok := r.read(int(ctLen))
	if !ok {
		return nil, ErrMalformed
	}
	sigInputEnd := r.pos

	sigLen, ok := r.readU16()
	if !ok || sigLen != SigSize {
		return nil, ErrMalformed
	}
	sig, ok := r.read(int(sigLen))
	if !ok {
		return nil, ErrMalformed
	}

	// Reject trailing bytes — the envelope must be exactly the parsed length.
	if r.pos != len(raw) {
		return nil, ErrMalformed
	}

	return &Envelope{
		Flags:         flags,
		KEMCiphertext: kemCt,
		Nonce:         nonce,
		PolicyBlob:    policyBlob,
		Ciphertext:    ciphertext,
		Signature:     sig,
		SigInputEnd:   sigInputEnd,
	}, nil
}

// assemblePrefix builds the byte slice that the signature is computed over:
// everything from the magic up through the ciphertext. Used by Seal.
func assemblePrefix(flags byte, kemCt, nonce, policyBlob, ciphertext []byte) ([]byte, error) {
	if len(kemCt) != KEMCtSize {
		return nil, ErrMalformed
	}
	if len(nonce) != NonceSize {
		return nil, ErrMalformed
	}
	if len(policyBlob) > 0xFFFF {
		return nil, ErrMalformed
	}
	if len(ciphertext) > MaxEnvelopeSize {
		return nil, ErrMalformed
	}

	total := MagicSize + FlagsSize + KEMCtLenSize + KEMCtSize + NonceSize +
		PolicyLenSize + len(policyBlob) + CtLenSize + len(ciphertext)
	buf := make([]byte, 0, total)
	buf = append(buf, Magic...)
	buf = append(buf, flags)
	buf = binary.BigEndian.AppendUint32(buf, KEMCtSize)
	buf = append(buf, kemCt...)
	buf = append(buf, nonce...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(policyBlob)))
	buf = append(buf, policyBlob...)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(ciphertext)))
	buf = append(buf, ciphertext...)
	return buf, nil
}

// appendSignature appends sig_len || signature and enforces the 16 MiB cap.
func appendSignature(prefix, sig []byte) ([]byte, error) {
	if len(sig) != SigSize {
		return nil, ErrMalformed
	}
	out := make([]byte, 0, len(prefix)+SigLenSize+SigSize)
	out = append(out, prefix...)
	out = binary.BigEndian.AppendUint16(out, SigSize)
	out = append(out, sig...)
	if len(out) > MaxEnvelopeSize {
		return nil, ErrMalformed
	}
	return out, nil
}

// --- bounded reader ------------------------------------------------------

type reader struct {
	buf []byte
	pos int
}

func (r *reader) read(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, false
	}
	s := r.buf[r.pos : r.pos+n]
	r.pos += n
	return s, true
}

func (r *reader) readByte() (byte, bool) {
	if r.pos+1 > len(r.buf) {
		return 0, false
	}
	b := r.buf[r.pos]
	r.pos++
	return b, true
}

func (r *reader) readU16() (uint16, bool) {
	s, ok := r.read(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(s), true
}

func (r *reader) readU32() (uint32, bool) {
	s, ok := r.read(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(s), true
}
