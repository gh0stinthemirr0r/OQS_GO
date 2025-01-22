// OQS-GO
// Aaron Stovall

package oqs

import (
	"C"
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
}

// OQS_AES_set_callbacks sets the callback functions for AES operations.
// This function may be called before OQS_init to switch the
// cryptographic provider for AES operations.
func OQS_AES_set_callbacks(newCallbacks *OQS_AESCallbacks) {
	// Implementation to set the callbacks would go here.
	// This could involve storing the callbacks in a global variable
	// or a context that can be accessed by the AES operations.
}
