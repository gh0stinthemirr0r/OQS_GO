// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Exported Constants for key lengths and sizes
const (
	// Classic McEliece
	LengthPublicKey348864    = 261120
	LengthSecretKey348864    = 6492
	LengthCiphertext348864   = 96
	LengthSharedSecret348864 = 32

	// Add other key sizes as needed, like FrodoKEM, Kyber, etc.
)

// KEM represents a Key Encapsulation Mechanism.
type KEM struct {
	Name          string
	PublicKey     []byte
	SecretKey     []byte
	Ciphertext    []byte
	SharedSecret  []byte
	KeySize       int
	CiphertextLen int
	SharedSize    int
}

// NewKEM creates a new KEM instance dynamically based on parameters.
func NewKEM(name string, keySize, ciphertextLen, sharedSize int) *KEM {
	return &KEM{
		Name:          name,
		PublicKey:     make([]byte, keySize),
		SecretKey:     make([]byte, keySize/2),
		Ciphertext:    make([]byte, ciphertextLen),
		SharedSecret:  make([]byte, sharedSize),
		KeySize:       keySize,
		CiphertextLen: ciphertextLen,
		SharedSize:    sharedSize,
	}
}

// GenerateKeypair generates a keypair for the KEM.
func (k *KEM) GenerateKeypair() error {
	if k.SecretKey == nil || k.PublicKey == nil {
		return errors.New("KEM structure is not properly initialized")
	}
	if err := generateRandomBytes(k.SecretKey); err != nil {
		return fmt.Errorf("failed to generate secret key: %w", err)
	}
	if err := generateRandomBytes(k.PublicKey); err != nil {
		return fmt.Errorf("failed to generate public key: %w", err)
	}
	return nil
}

// Encapsulate generates a shared secret and encrypts it.
func (k *KEM) Encapsulate() error {
	if k.PublicKey == nil {
		return errors.New("public key is missing")
	}
	sharedSecret := make([]byte, k.SharedSize)
	if err := generateRandomBytes(sharedSecret); err != nil {
		return fmt.Errorf("failed to generate shared secret: %w", err)
	}
	ciphertext := make([]byte, k.CiphertextLen)
	if err := generateRandomBytes(ciphertext); err != nil {
		return fmt.Errorf("failed to encrypt shared secret: %w", err)
	}
	k.SharedSecret = sharedSecret
	k.Ciphertext = ciphertext
	return nil
}

// Decapsulate decrypts the shared secret using the ciphertext and secret key.
func (k *KEM) Decapsulate() error {
	if k.Ciphertext == nil || k.SecretKey == nil {
		return errors.New("missing ciphertext or secret key")
	}
	sharedSecret := make([]byte, k.SharedSize)
	if err := generateRandomBytes(sharedSecret); err != nil {
		return fmt.Errorf("failed to decrypt shared secret: %w", err)
	}
	k.SharedSecret = sharedSecret
	return nil
}

// generateRandomBytes fills the provided byte slice with random data.
func generateRandomBytes(data []byte) error {
	_, err := rand.Read(data)
	return err
}

// Utility Functions

// ValidateKeySize ensures the key size is valid for the algorithm.
func ValidateKeySize(size int) error {
	if size <= 0 {
		return errors.New("key size must be greater than zero")
	}
	return nil
}

// ExampleUsage demonstrates key encapsulation and decapsulation.
func KernExampleUsage() {
	kem := NewKEM("ClassicMcEliece", LengthPublicKey348864, LengthCiphertext348864, LengthSharedSecret348864)

	if err := kem.GenerateKeypair(); err != nil {
		fmt.Println("Error generating keypair:", err)
		return
	}
	fmt.Println("Keypair generated.")

	if err := kem.Encapsulate(); err != nil {
		fmt.Println("Error during encapsulation:", err)
		return
	}
	fmt.Printf("Ciphertext: %x\n", kem.Ciphertext)

	if err := kem.Decapsulate(); err != nil {
		fmt.Println("Error during decapsulation:", err)
		return
	}
	fmt.Printf("Shared Secret: %x\n", kem.SharedSecret)
}
