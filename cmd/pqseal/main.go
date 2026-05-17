// Command pqseal serves the §5 HTTP API: POST /seal and POST /unseal over
// plain HTTP (the spec is explicit that TLS and auth are out of scope).
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"

	"pqseal/internal/envelope"
	"pqseal/internal/keystore"
	"pqseal/internal/policy"
)

// maxRequestBytes bounds the request body. A 16 MiB envelope base64-encoded
// is ~22 MiB; 32 MiB leaves headroom for the JSON wrapper while still
// matching the spirit of §4's 16 MiB envelope cap.
const maxRequestBytes = 32 * 1024 * 1024

// §5.2 error vocabulary. The user-visible error string must be drawn from
// this list and no other.
const (
	errMalformed    = "malformed envelope"
	errAuthFailed   = "authentication failed"
	errPolicyDenied = "policy denied"
	errUnknownKey   = "unknown key"
)

// --- request / response shapes ------------------------------------------

type sealReq struct {
	RecipientEKID string `json:"recipient_ek_id"`
	IssuerPrivID  string `json:"issuer_priv_id"`
	Policy        string `json:"policy"`
	Compress      bool   `json:"compress"`
	PayloadB64    string `json:"payload_b64"`
}

type sealResp struct {
	EnvelopeB64 string `json:"envelope_b64"`
}

type unsealReq struct {
	EnvelopeB64   string            `json:"envelope_b64"`
	RecipientDKID string            `json:"recipient_dk_id"`
	IssuerPubID   string            `json:"issuer_pub_id"`
	Claims        map[string]string `json:"claims"`
}

type unsealResp struct {
	PayloadB64 string `json:"payload_b64"`
}

type errResp struct {
	Error string `json:"error"`
}

// --- server -------------------------------------------------------------

type server struct {
	ks *keystore.Store
}

// NewHandler returns the configured HTTP handler. Exported separately from
// main so the test package can exercise the full pipeline via httptest.
func NewHandler(ks *keystore.Store) http.Handler {
	s := &server{ks: ks}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /seal", s.handleSeal)
	mux.HandleFunc("POST /unseal", s.handleUnseal)
	return mux
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errResp{Error: msg})
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// --- /seal --------------------------------------------------------------

func (s *server) handleSeal(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	var req sealReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errMalformed)
		return
	}

	payload, err := base64.StdEncoding.DecodeString(req.PayloadB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errMalformed)
		return
	}

	// Reject invalid policies at seal time with HTTP 400 (§6.2).
	if _, err := policy.Parse(req.Policy); err != nil {
		writeError(w, http.StatusBadRequest, errMalformed)
		return
	}

	ek, err := s.ks.EK(req.RecipientEKID)
	if err != nil {
		writeError(w, http.StatusNotFound, errUnknownKey)
		return
	}
	priv, err := s.ks.IssuerPriv(req.IssuerPrivID)
	if err != nil {
		writeError(w, http.StatusNotFound, errUnknownKey)
		return
	}

	env, err := envelope.Seal(envelope.SealParams{
		EK:         ek,
		IssuerPriv: priv,
		Policy:     req.Policy,
		Plaintext:  payload,
		Compress:   req.Compress,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, errMalformed)
		return
	}

	writeJSON(w, sealResp{EnvelopeB64: base64.StdEncoding.EncodeToString(env)})
}

// --- /unseal ------------------------------------------------------------
//
// Order of operations (§8.2):
//
//   1. Parse envelope structure → ErrMalformed.
//   2. Verify ML-DSA-65 signature → ErrAuthFailed.
//   3. Parse and evaluate policy from envelope.PolicyBlob.
//      Parse failure → ErrMalformed. Denied → ErrPolicyDenied.
//   4. ML-KEM-768 decapsulation → ErrAuthFailed.
//   5-7. HKDF → AEAD-open → optional inflate.
//
// Signature is verified before policy so a tampered policy_blob is rejected
// here. Policy is evaluated before decapsulation so a caller whose claims
// fail the policy never triggers a Decapsulate on DK.
func (s *server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	var req unsealReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, errMalformed)
		return
	}

	raw, err := base64.StdEncoding.DecodeString(req.EnvelopeB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errMalformed)
		return
	}

	// 1. Structural validation.
	env, err := envelope.ParseEnvelope(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, errMalformed)
		return
	}

	// Key lookups happen after structural validation but before any crypto
	// work that could distinguish failure modes.
	dk, err := s.ks.DK(req.RecipientDKID)
	if err != nil {
		writeError(w, http.StatusNotFound, errUnknownKey)
		return
	}
	pub, err := s.ks.IssuerPub(req.IssuerPubID)
	if err != nil {
		writeError(w, http.StatusNotFound, errUnknownKey)
		return
	}

	// 2. Verify signature.
	if err := env.VerifySignature(pub, raw); err != nil {
		writeError(w, http.StatusUnauthorized, errAuthFailed)
		return
	}

	// 3. Policy: parse, then evaluate.
	pol, err := policy.Parse(string(env.PolicyBlob))
	if err != nil {
		writeError(w, http.StatusBadRequest, errMalformed)
		return
	}
	if !pol.Eval(req.Claims) {
		writeError(w, http.StatusForbidden, errPolicyDenied)
		return
	}

	// 4-7. Decapsulate, derive key, AEAD-open, maybe inflate.
	plaintext, err := env.Decrypt(dk)
	if err != nil {
		switch {
		case errors.Is(err, envelope.ErrMalformed):
			writeError(w, http.StatusBadRequest, errMalformed)
		default:
			writeError(w, http.StatusUnauthorized, errAuthFailed)
		}
		return
	}

	writeJSON(w, unsealResp{PayloadB64: base64.StdEncoding.EncodeToString(plaintext)})
}

// --- main ---------------------------------------------------------------

func main() {
	addr := flag.String("addr", ":8443", "HTTP listen address (plain HTTP, no TLS)")
	dir := flag.String("keystore", "./testkeys", "directory of key files")
	flag.Parse()

	ks, err := keystore.Load(*dir)
	if err != nil {
		log.Fatalf("pqseal: %v", err)
	}

	log.Printf("pqseal listening on %s (keystore=%s)", *addr, *dir)
	if err := http.ListenAndServe(*addr, NewHandler(ks)); err != nil {
		log.Fatal(err)
	}
}
