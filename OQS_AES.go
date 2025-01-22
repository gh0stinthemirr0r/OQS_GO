// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"unsafe"
)

// OQS_AESCallbacks defines the callback API for AES operations.
type OQS_AESCallbacks struct {
	AES128_ECB_load_schedule   func(key []byte, ctx **unsafe.Pointer)
	AES128_CTR_inc_init        func(key []byte, ctx **unsafe.Pointer)
	AES128_CTR_inc_iv          func(iv []byte, ivLen int, ctx unsafe.Pointer)
	AES128_CTR_inc_ivu64       func(iv uint64, ctx unsafe.Pointer)
	AES128_free_schedule       func(ctx unsafe.Pointer)
	AES128_ECB_enc             func(plaintext []byte, plaintextLen int, key []byte, ciphertext []byte)
	AES128_ECB_enc_sch         func(plaintext []byte, plaintextLen int, schedule unsafe.Pointer, ciphertext []byte)
	AES128_CTR_inc_stream_iv   func(iv []byte, ivLen int, ctx unsafe.Pointer, out []byte, outLen int)
	AES256_ECB_load_schedule   func(key []byte, ctx **unsafe.Pointer)
	AES256_CTR_inc_init        func(key []byte, ctx **unsafe.Pointer)
	AES256_CTR_inc_iv          func(iv []byte, ivLen int, ctx unsafe.Pointer)
	AES256_CTR_inc_ivu64       func(iv uint64, ctx unsafe.Pointer)
	AES256_free_schedule       func(ctx unsafe.Pointer)
	AES256_ECB_enc             func(plaintext []byte, plaintextLen int, key []byte, ciphertext []byte)
	AES256_ECB_enc_sch         func(plaintext []byte, plaintextLen int, schedule unsafe.Pointer, ciphertext []byte)
	AES256_CTR_inc_stream_iv   func(iv []byte, ivLen int, ctx unsafe.Pointer, out []byte, outLen int)
	AES256_CTR_inc_stream_blks func(ctx unsafe.Pointer, out []byte, outBlks int)
	AES_GCM_encrypt            func(plaintext []byte, key []byte, nonce []byte, additionalData []byte) ([]byte, error)
	AES_GCM_decrypt            func(ciphertext []byte, key []byte, nonce []byte, additionalData []byte) ([]byte, error)
	AES_EncryptAndSign         func(plaintext []byte, key []byte, nonce []byte, additionalData []byte, signKey []byte) ([]byte, string, error)
	AES_DecryptAndVerify       func(ciphertext []byte, key []byte, nonce []byte, additionalData []byte, publicKey []byte, signature string) ([]byte, error)
}

// OQS_AES_set_callbacks sets the callback functions for AES operations.
func OQS_AES_set_callbacks(newCallbacks *OQS_AESCallbacks) error {
	if newCallbacks == nil {
		return errors.New("invalid AES callbacks: nil")
	}
	currentAESCallbacks = newCallbacks
	return nil
}

// AES GCM Encryption, Signing, Decryption, and Verification Implementation

// AES_EncryptAndSign encrypts the plaintext and signs it.
func AES_EncryptAndSign(plaintext []byte, key []byte, nonce []byte, additionalData []byte, signKey []byte) ([]byte, string, error) {
	ciphertext, err := AES_GCM_encrypt(plaintext, key, nonce, additionalData)
	if err != nil {
		return nil, "", err
	}

	signature, err := Sign(signKey, plaintext)
	if err != nil {
		return nil, "", err
	}

	return ciphertext, signature, nil
}

// AES_DecryptAndVerify decrypts the ciphertext and verifies the signature.
func AES_DecryptAndVerify(ciphertext []byte, key []byte, nonce []byte, additionalData []byte, publicKey []byte, signature string) ([]byte, error) {
	plaintext, err := AES_GCM_decrypt(ciphertext, key, nonce, additionalData)
	if err != nil {
		return nil, err
	}

	isValid, err := Verify(publicKey, plaintext, signature)
	if err != nil {
		return nil, err
	}
	if !isValid {
		return nil, errors.New("signature verification failed")
	}

	return plaintext, nil
}

// AES GCM Encryption and Decryption Implementation

// AES_GCM_encrypt encrypts plaintext using AES-GCM mode.
func AES_GCM_encrypt(plaintext []byte, key []byte, nonce []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// AES_GCM_decrypt decrypts ciphertext using AES-GCM mode.
func AES_GCM_decrypt(ciphertext []byte, key []byte, nonce []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// Utility Functions

// ValidateAESKey validates the AES key length.
func ValidateAESKey(key []byte) error {
	switch len(key) {
	case 16, 24, 32: // 128-bit, 192-bit, 256-bit
		return nil
	default:
		return errors.New("invalid AES key length")
	}
}

// ValidateNonce validates the nonce length for AES-GCM.
func ValidateNonce(nonce []byte) error {
	if len(nonce) != 12 {
		return errors.New("invalid nonce length for AES-GCM")
	}
	return nil
}

// SecureKeyRotation rotates the encryption key securely.
func SecureKeyRotation(oldKey []byte) ([]byte, error) {
	newKey := make([]byte, len(oldKey))
	_, err := rand.Read(newKey)
	if err != nil {
		return nil, errors.New("failed to generate new key")
	}
	return newKey, nil
}

// Global variable for current AES callbacks
var currentAESCallbacks *OQS_AESCallbacks

// Example Usage
func Example() {
	key := []byte("examplekey123456") // 128-bit key
	nonce := []byte("exampleNonce12") // 12-byte nonce
	plaintext := []byte("Hello, World!")
	additionalData := []byte("Additional")

	ciphertext, signature, err := AES_EncryptAndSign(plaintext, key, nonce, additionalData, key)
	if err != nil {
		fmt.Println("Encryption and signing failed:", err)
		return
	}
	fmt.Println("Ciphertext:", ciphertext)
	fmt.Println("Signature:", signature)

	decrypted, err := AES_DecryptAndVerify(ciphertext, key, nonce, additionalData, key, signature)
	if err != nil {
		fmt.Println("Decryption and verification failed:", err)
		return
	}
	fmt.Println("Decrypted text:", string(decrypted))
}
