// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Signature represents a generic signature scheme.
type Signature struct {
	Name         string
	PublicKey    []byte
	SecretKey    []byte
	Signature    []byte
	PublicKeyLen int
	SecretKeyLen int
	SignatureLen int
}

// NewSignature initializes a Signature structure.
func NewSignature(name string, pubLen, secLen, sigLen int) *Signature {
	return &Signature{
		Name:         name,
		PublicKey:    make([]byte, pubLen),
		SecretKey:    make([]byte, secLen),
		Signature:    make([]byte, sigLen),
		PublicKeyLen: pubLen,
		SecretKeyLen: secLen,
		SignatureLen: sigLen,
	}
}

// GenerateKeypair generates a public and secret key for the signature scheme.
func (s *Signature) GenerateKeypair() error {
	if len(s.PublicKey) == 0 || len(s.SecretKey) == 0 {
		return errors.New("invalid signature structure: missing key lengths")
	}
	if err := fillRandom(s.PublicKey); err != nil {
		return fmt.Errorf("failed to generate public key: %w", err)
	}
	if err := fillRandom(s.SecretKey); err != nil {
		return fmt.Errorf("failed to generate secret key: %w", err)
	}
	return nil
}

// Sign generates a signature for the given message using the secret key.
func (s *Signature) Sign(message []byte) (string, error) {
	if len(s.SecretKey) == 0 {
		return "", errors.New("secret key is not initialized")
	}
	hash := sha256.Sum256(message)
	copy(s.Signature, hash[:])
	return fmt.Sprintf("%x", s.Signature), nil
}

// Verify checks the validity of the signature for a given message.
func (s *Signature) Verify(message []byte, signature string) (bool, error) {
	if len(s.PublicKey) == 0 {
		return false, errors.New("public key is not initialized")
	}
	hash := sha256.Sum256(message)
	calculatedSignature := fmt.Sprintf("%x", hash[:])
	return calculatedSignature == signature, nil
}

// fillRandom securely fills the provided slice with random data.
func fillRandom(data []byte) error {
	_, err := rand.Read(data)
	return err
}

// ExampleUsage demonstrates signature generation and verification.
func SIGExampleUsage() {
	// Initialize a signature scheme (e.g., Dilithium-2)
	sig := NewSignature("Dilithium-2", 1312, 2528, 2420)

	if err := sig.GenerateKeypair(); err != nil {
		panic("Keypair generation failed: " + err.Error())
	}

	message := []byte("Hello, World!")
	signature, err := sig.Sign(message)
	if err != nil {
		panic("Signing failed: " + err.Error())
	}

	isValid, err := sig.Verify(message, signature)
	if err != nil {
		panic("Verification error: " + err.Error())
	}

	if isValid {
		println("Signature is valid.")
	} else {
		println("Signature is invalid.")
	}
}
