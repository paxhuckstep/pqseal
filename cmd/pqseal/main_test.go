package main

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"pqseal/internal/keystore"
)

// buildStore writes a fresh keypair set into a temp dir and loads it.
func buildStore(t *testing.T) *keystore.Store {
	t.Helper()
	dir := t.TempDir()

	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "alice.mlkem.ek"), dk.EncapsulationKey().Bytes())
	mustWrite(t, filepath.Join(dir, "alice.mlkem.dk"), dk.Bytes())

	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB, _ := pub.MarshalBinary()
	privB, _ := priv.MarshalBinary()
	mustWrite(t, filepath.Join(dir, "issuer-1.mldsa.pub"), pubB)
	mustWrite(t, filepath.Join(dir, "issuer-1.mldsa.priv"), privB)

	ks, err := keystore.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func doJSON(t *testing.T, h http.Handler, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	resp := map[string]any{}
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode resp: %v (body=%q)", err, w.Body.String())
		}
	}
	return w.Code, resp
}

// Happy-path: seal then unseal with claims that satisfy the policy.
func TestHTTPRoundTrip(t *testing.T) {
	h := NewHandler(buildStore(t))

	payload := []byte("classified-but-fine")
	code, resp := doJSON(t, h, "POST", "/seal", map[string]any{
		"recipient_ek_id": "alice",
		"issuer_priv_id":  "issuer-1",
		"policy":          "clearance >= 'SECRET' AND citizenship == 'USA'",
		"compress":        true,
		"payload_b64":     base64.StdEncoding.EncodeToString(payload),
	})
	if code != 200 {
		t.Fatalf("/seal status %d: %v", code, resp)
	}
	envB64, _ := resp["envelope_b64"].(string)
	if envB64 == "" {
		t.Fatal("missing envelope_b64")
	}

	code, resp = doJSON(t, h, "POST", "/unseal", map[string]any{
		"envelope_b64":    envB64,
		"recipient_dk_id": "alice",
		"issuer_pub_id":   "issuer-1",
		"claims": map[string]string{
			"clearance":   "TOP_SECRET",
			"citizenship": "USA",
		},
	})
	if code != 200 {
		t.Fatalf("/unseal status %d: %v", code, resp)
	}
	gotB64, _ := resp["payload_b64"].(string)
	got, err := base64.StdEncoding.DecodeString(gotB64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("round-trip mismatch: got %q want %q", got, payload)
	}
}

// §9: claims that fail the policy → "policy denied" 403.
func TestHTTPPolicyDenied(t *testing.T) {
	h := NewHandler(buildStore(t))
	code, resp := doJSON(t, h, "POST", "/seal", map[string]any{
		"recipient_ek_id": "alice",
		"issuer_priv_id":  "issuer-1",
		"policy":          "clearance >= 'TOP_SECRET'",
		"payload_b64":     base64.StdEncoding.EncodeToString([]byte("x")),
	})
	if code != 200 {
		t.Fatalf("/seal: %d %v", code, resp)
	}
	envB64 := resp["envelope_b64"].(string)

	code, resp = doJSON(t, h, "POST", "/unseal", map[string]any{
		"envelope_b64":    envB64,
		"recipient_dk_id": "alice",
		"issuer_pub_id":   "issuer-1",
		"claims":          map[string]string{"clearance": "SECRET"},
	})
	if code != 403 {
		t.Fatalf("expected 403, got %d (%v)", code, resp)
	}
	if resp["error"] != "policy denied" {
		t.Errorf("expected 'policy denied', got %v", resp["error"])
	}
}

// §9: unknown key id → 404.
func TestHTTPUnknownKey(t *testing.T) {
	h := NewHandler(buildStore(t))
	code, resp := doJSON(t, h, "POST", "/seal", map[string]any{
		"recipient_ek_id": "nobody",
		"issuer_priv_id":  "issuer-1",
		"policy":          "x == 'y'",
		"payload_b64":     "",
	})
	if code != 404 {
		t.Fatalf("expected 404, got %d", code)
	}
	if resp["error"] != "unknown key" {
		t.Errorf("expected 'unknown key', got %v", resp["error"])
	}
}

// §9: tampered envelope → "authentication failed" 401.
func TestHTTPCiphertextTamper(t *testing.T) {
	h := NewHandler(buildStore(t))
	code, resp := doJSON(t, h, "POST", "/seal", map[string]any{
		"recipient_ek_id": "alice",
		"issuer_priv_id":  "issuer-1",
		"policy":          "x == 'y' OR NOT x == 'y'", // tautology
		"payload_b64":     base64.StdEncoding.EncodeToString([]byte("data")),
	})
	if code != 200 {
		t.Fatalf("/seal: %d %v", code, resp)
	}
	envB64 := resp["envelope_b64"].(string)
	raw, _ := base64.StdEncoding.DecodeString(envB64)
	raw[len(raw)/2] ^= 0x01 // flip somewhere inside (likely the signature)
	envB64 = base64.StdEncoding.EncodeToString(raw)

	code, resp = doJSON(t, h, "POST", "/unseal", map[string]any{
		"envelope_b64":    envB64,
		"recipient_dk_id": "alice",
		"issuer_pub_id":   "issuer-1",
		"claims":          map[string]string{"x": "anything"},
	})
	if code != 401 {
		t.Fatalf("expected 401, got %d", code)
	}
	if resp["error"] != "authentication failed" {
		t.Errorf("expected 'authentication failed', got %v", resp["error"])
	}
}

// §9: bad magic → 400 "malformed envelope".
func TestHTTPBadMagic(t *testing.T) {
	h := NewHandler(buildStore(t))
	// Manufacture a buffer starting with PQS2 and full of zeros.
	bad := make([]byte, 4500)
	copy(bad, "PQS2")
	code, resp := doJSON(t, h, "POST", "/unseal", map[string]any{
		"envelope_b64":    base64.StdEncoding.EncodeToString(bad),
		"recipient_dk_id": "alice",
		"issuer_pub_id":   "issuer-1",
		"claims":          map[string]string{},
	})
	if code != 400 {
		t.Fatalf("expected 400, got %d", code)
	}
	if resp["error"] != "malformed envelope" {
		t.Errorf("expected 'malformed envelope', got %v", resp["error"])
	}
}

// §6.2: invalid policy at seal time → 400.
func TestHTTPSealInvalidPolicy(t *testing.T) {
	h := NewHandler(buildStore(t))
	code, resp := doJSON(t, h, "POST", "/seal", map[string]any{
		"recipient_ek_id": "alice",
		"issuer_priv_id":  "issuer-1",
		"policy":          "this is not a policy",
		"payload_b64":     "",
	})
	if code != 400 {
		t.Fatalf("expected 400, got %d (%v)", code, resp)
	}
	if !strings.Contains(resp["error"].(string), "malformed") {
		t.Errorf("expected malformed-envelope-style error, got %v", resp["error"])
	}
}
