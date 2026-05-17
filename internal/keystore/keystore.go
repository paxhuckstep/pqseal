// Package keystore loads ML-KEM-768 and ML-DSA-65 key material from a flat
// directory at startup, per §7 of the challenge spec. There is no hot reload.
package keystore

import (
	"crypto/mlkem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// File-suffix conventions from §7.
const (
	suffixEK   = ".mlkem.ek"
	suffixDK   = ".mlkem.dk"
	suffixPub  = ".mldsa.pub"
	suffixPriv = ".mldsa.priv"

	// Fixed public-key sizes — the spec requires the entire keystore be
	// rejected at startup if a public-key file has the wrong size.
	EKSize  = 1184
	PubSize = 1952
)

// ErrUnknownKey is returned by all lookup methods when an id is absent.
// The HTTP layer maps this to the §5.2 "unknown key" 404 response.
var ErrUnknownKey = errors.New("unknown key")

// Store is the in-memory keystore.
type Store struct {
	eks   map[string]*mlkem.EncapsulationKey768
	dks   map[string]*mlkem.DecapsulationKey768
	pubs  map[string]*mldsa65.PublicKey
	privs map[string]*mldsa65.PrivateKey
}

// Load reads every key file in dir. Files whose suffix is not one of the
// four conventions are ignored. Any malformed key file fails the entire
// load.
func Load(dir string) (*Store, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("keystore: read dir %q: %w", dir, err)
	}

	s := &Store{
		eks:   make(map[string]*mlkem.EncapsulationKey768),
		dks:   make(map[string]*mlkem.DecapsulationKey768),
		pubs:  make(map[string]*mldsa65.PublicKey),
		privs: make(map[string]*mldsa65.PrivateKey),
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		path := filepath.Join(dir, name)

		switch {
		case strings.HasSuffix(name, suffixEK):
			id := strings.TrimSuffix(name, suffixEK)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("keystore: read %s: %w", name, err)
			}
			if len(data) != EKSize {
				return nil, fmt.Errorf("keystore: %s wrong size %d, want %d", name, len(data), EKSize)
			}
			ek, err := mlkem.NewEncapsulationKey768(data)
			if err != nil {
				return nil, fmt.Errorf("keystore: parse %s: %w", name, err)
			}
			s.eks[id] = ek

		case strings.HasSuffix(name, suffixDK):
			id := strings.TrimSuffix(name, suffixDK)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("keystore: read %s: %w", name, err)
			}
			dk, err := mlkem.NewDecapsulationKey768(data)
			if err != nil {
				return nil, fmt.Errorf("keystore: parse %s: %w", name, err)
			}
			s.dks[id] = dk

		case strings.HasSuffix(name, suffixPub):
			id := strings.TrimSuffix(name, suffixPub)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("keystore: read %s: %w", name, err)
			}
			if len(data) != PubSize {
				return nil, fmt.Errorf("keystore: %s wrong size %d, want %d", name, len(data), PubSize)
			}
			pub := new(mldsa65.PublicKey)
			if err := pub.UnmarshalBinary(data); err != nil {
				return nil, fmt.Errorf("keystore: parse %s: %w", name, err)
			}
			s.pubs[id] = pub

		case strings.HasSuffix(name, suffixPriv):
			id := strings.TrimSuffix(name, suffixPriv)
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("keystore: read %s: %w", name, err)
			}
			priv := new(mldsa65.PrivateKey)
			if err := priv.UnmarshalBinary(data); err != nil {
				return nil, fmt.Errorf("keystore: parse %s: %w", name, err)
			}
			s.privs[id] = priv
		}
	}
	return s, nil
}

// EK returns the recipient encapsulation key with the given id, or
// ErrUnknownKey if no such key exists.
func (s *Store) EK(id string) (*mlkem.EncapsulationKey768, error) {
	ek, ok := s.eks[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	return ek, nil
}

// DK returns the recipient decapsulation key with the given id.
func (s *Store) DK(id string) (*mlkem.DecapsulationKey768, error) {
	dk, ok := s.dks[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	return dk, nil
}

// IssuerPub returns the issuer ML-DSA-65 public key with the given id.
func (s *Store) IssuerPub(id string) (*mldsa65.PublicKey, error) {
	pub, ok := s.pubs[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	return pub, nil
}

// IssuerPriv returns the issuer ML-DSA-65 private key with the given id.
func (s *Store) IssuerPriv(id string) (*mldsa65.PrivateKey, error) {
	priv, ok := s.privs[id]
	if !ok {
		return nil, ErrUnknownKey
	}
	return priv, nil
}
