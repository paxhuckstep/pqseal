package envelope

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// SealParams collects the inputs to Seal.
type SealParams struct {
	EK         *mlkem.EncapsulationKey768
	IssuerPriv *mldsa65.PrivateKey
	Policy     string // raw UTF-8 policy expression; embedded verbatim
	Plaintext  []byte
	Compress   bool
}

// Seal implements §8.1. Two calls with identical inputs produce different
// envelopes because step 1 freshly randomizes the KEM encapsulation and
// step 3 generates a fresh nonce.
func Seal(p SealParams) ([]byte, error) {
	// 1. Encapsulate to the recipient's public key.
	sharedSecret, kemCiphertext := p.EK.Encapsulate()

	// 2. Derive a 32-byte AES key via HKDF-SHA256.
	key, err := hkdf.Key(sha256.New, sharedSecret, kemCiphertext, HKDFInfo, 32)
	if err != nil {
		return nil, err
	}

	// 3. Fresh 12-byte nonce.
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// 4. Optional deflate compression of the plaintext.
	flags := byte(0)
	payload := p.Plaintext
	if p.Compress {
		flags |= FlagCompressed
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(p.Plaintext); err != nil {
			return nil, err
		}
		if err := w.Close(); err != nil {
			return nil, err
		}
		payload = buf.Bytes()
	}

	// 5. AES-256-GCM with the policy bytes as additional data.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	policyBlob := []byte(p.Policy)
	if len(policyBlob) > 0xFFFF {
		return nil, ErrMalformed
	}
	ciphertext := aead.Seal(nil, nonce, payload, policyBlob)

	// 6. Assemble the signed prefix.
	prefix, err := assemblePrefix(flags, kemCiphertext, nonce, policyBlob, ciphertext)
	if err != nil {
		return nil, err
	}

	// 7. SHA-256, sign, append.
	digest := sha256.Sum256(prefix)
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(p.IssuerPriv, digest[:], nil, false, sig)

	return appendSignature(prefix, sig)
}

// VerifySignature checks the ML-DSA-65 signature over SHA-256 of the
// prefix bytes in raw. raw must be the same buffer originally passed to
// ParseEnvelope.
func (e *Envelope) VerifySignature(issuerPub *mldsa65.PublicKey, raw []byte) error {
	if e.SigInputEnd <= 0 || e.SigInputEnd > len(raw) {
		return ErrMalformed
	}
	digest := sha256.Sum256(raw[:e.SigInputEnd])
	if !mldsa65.Verify(issuerPub, digest[:], nil, e.Signature) {
		return ErrAuthFailed
	}
	return nil
}

// Decrypt performs steps 4 through 7 of §8.2: decapsulate, derive the AES
// key, AEAD-open with the policy bytes as additional data, and (if the
// compressed flag is set) inflate the plaintext.
//
// Per §5.2 we collapse decapsulation failure and AEAD authentication
// failure into the same ErrAuthFailed sentinel so a caller cannot use the
// error message as an oracle. Inflate failure maps to ErrMalformed because
// it indicates a corrupt envelope, not an authentication failure.
func (e *Envelope) Decrypt(dk *mlkem.DecapsulationKey768) ([]byte, error) {
	sharedSecret, err := dk.Decapsulate(e.KEMCiphertext)
	if err != nil {
		return nil, ErrAuthFailed
	}

	key, err := hkdf.Key(sha256.New, sharedSecret, e.KEMCiphertext, HKDFInfo, 32)
	if err != nil {
		return nil, ErrAuthFailed
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrAuthFailed
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrAuthFailed
	}
	plaintext, err := aead.Open(nil, e.Nonce, e.Ciphertext, e.PolicyBlob)
	if err != nil {
		return nil, ErrAuthFailed
	}

	if e.Flags&FlagCompressed != 0 {
		r := flate.NewReader(bytes.NewReader(plaintext))
		out, err := io.ReadAll(r)
		closeErr := r.Close()
		if err != nil || closeErr != nil {
			return nil, ErrMalformed
		}
		plaintext = out
	}
	return plaintext, nil
}
