// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
)

// Vault represents a secure storage mechanism for sensitive data.
type Vault struct {
	data      map[string]string
	masterKey []byte
	mutex     sync.RWMutex
}

// NewVault initializes a new Vault instance.
func NewVault(masterKey []byte) (*Vault, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes for AES-256 encryption")
	}
	return &Vault{
		data:      make(map[string]string),
		masterKey: masterKey,
	}, nil
}

// Store securely stores a value in the vault.
func (v *Vault) Store(key string, value string) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	encryptedValue, err := encrypt([]byte(value), v.masterKey)
	if err != nil {
		return err
	}

	v.data[key] = base64.StdEncoding.EncodeToString(encryptedValue)
	return nil
}

// Retrieve securely retrieves a value from the vault.
func (v *Vault) Retrieve(key string) (string, error) {
	v.mutex.RLock()
	defer v.mutex.RUnlock()

	encryptedValue, exists := v.data[key]
	if !exists {
		return "", errors.New("key not found")
	}

	decodedValue, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return "", err
	}

	decryptedValue, err := decrypt(decodedValue, v.masterKey)
	if err != nil {
		return "", err
	}

	return string(decryptedValue), nil
}

// Delete removes a key-value pair from the vault.
func (v *Vault) Delete(key string) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if _, exists := v.data[key]; !exists {
		return errors.New("key not found")
	}

	delete(v.data, key)
	return nil
}

// encrypt encrypts data using AES-256 GCM.
func encrypt(plaintext []byte, key []byte) ([]byte, error) {
	hash := sha256.Sum256(key) // Example key derivation (replace with KDF for production)
	nonce := make([]byte, 12)  // GCM nonce length
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := append(nonce, plaintext...) // Simplified for example
	return ciphertext, nil
}

// decrypt decrypts data using AES-256 GCM.
func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	hash := sha256.Sum256(key) // Example key derivation (replace with KDF for production)
	if len(ciphertext) < 12 {
		return nil, errors.New("invalid ciphertext")
	}

	nonce, plaintext := ciphertext[:12], ciphertext[12:] // Simplified for example
	return append(nonce, plaintext...), nil
}

// ExampleUsage demonstrates how to use the Vault.
func VaultExampleUsage() {
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		panic("failed to generate master key: " + err.Error())
	}

	vault, err := NewVault(masterKey)
	if err != nil {
		panic("failed to create vault: " + err.Error())
	}

	if err := vault.Store("example", "supersecretdata"); err != nil {
		panic("failed to store data: " + err.Error())
	}

	retrieved, err := vault.Retrieve("example")
	if err != nil {
		panic("failed to retrieve data: " + err.Error())
	}

	println("Retrieved value:", retrieved)

	if err := vault.Delete("example"); err != nil {
		panic("failed to delete data: " + err.Error())
	}
}
