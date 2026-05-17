// Command pqseal-keygen writes a recipient ML-KEM-768 keypair and an issuer
// ML-DSA-65 keypair into the keystore directory using the file-naming
// conventions from §7.
package main

import (
	"crypto/mlkem"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func main() {
	dir := flag.String("dir", "./testkeys", "output keystore directory")
	recipient := flag.String("recipient", "alice", "recipient id (ML-KEM-768)")
	issuer := flag.String("issuer", "issuer-1", "issuer id (ML-DSA-65)")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatalf("mkdir: %v", err)
	}

	// ML-KEM-768 recipient keypair.
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatalf("mlkem.GenerateKey768: %v", err)
	}
	ek := dk.EncapsulationKey()
	writeFile(filepath.Join(*dir, *recipient+".mlkem.ek"), ek.Bytes())
	writeFile(filepath.Join(*dir, *recipient+".mlkem.dk"), dk.Bytes())

	// ML-DSA-65 issuer keypair.
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("mldsa65.GenerateKey: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		log.Fatalf("marshal pub: %v", err)
	}
	privBytes, err := priv.MarshalBinary()
	if err != nil {
		log.Fatalf("marshal priv: %v", err)
	}
	writeFile(filepath.Join(*dir, *issuer+".mldsa.pub"), pubBytes)
	writeFile(filepath.Join(*dir, *issuer+".mldsa.priv"), privBytes)

	fmt.Printf("wrote keypairs to %s:\n", *dir)
	fmt.Printf("  recipient %q: %s.mlkem.ek (%d B), %s.mlkem.dk (%d B)\n",
		*recipient, *recipient, len(ek.Bytes()), *recipient, len(dk.Bytes()))
	fmt.Printf("  issuer    %q: %s.mldsa.pub (%d B), %s.mldsa.priv (%d B)\n",
		*issuer, *issuer, len(pubBytes), *issuer, len(privBytes))
}

func writeFile(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		log.Fatalf("write %s: %v", path, err)
	}
}
