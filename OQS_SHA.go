// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
)

// SHA224Context holds the state for SHA-224 incremental hashing.
type SHA224Context struct {
	ctx     interface{} // Placeholder for internal state
	dataLen uint64      // Current number of bytes in data
	data    [128]byte   // Unprocessed data buffer
}

// SHA256Context holds the state for SHA-256 incremental hashing.
type SHA256Context struct {
	ctx     interface{} // Placeholder for internal state
	dataLen uint64      // Current number of bytes in data
	data    [128]byte   // Unprocessed data buffer
}

// SHA384Context holds the state for SHA-384 incremental hashing.
type SHA384Context struct {
	ctx     interface{} // Placeholder for internal state
	dataLen uint64      // Current number of bytes in data
	data    [128]byte   // Unprocessed data buffer
}

// SHA512Context holds the state for SHA-512 incremental hashing.
type SHA512Context struct {
	ctx     interface{} // Placeholder for internal state
	dataLen uint64      // Current number of bytes in data
	data    [128]byte   // Unprocessed data buffer
}

// SHA3_256Context holds the state for SHA3-256 incremental hashing.
type SHA3_256Context struct {
	ctx *sha3.State // Placeholder for internal state
}

// SHA3_384Context holds the state for SHA3-384 incremental hashing.
type SHA3_384Context struct {
	ctx *sha3.State // Placeholder for internal state
}

// SHA3_512Context holds the state for SHA3-512 incremental hashing.
type SHA3_512Context struct {
	ctx *sha3.State // Placeholder for internal state
}

// SHAKE128Context holds the state for SHAKE-128 incremental hashing.
type SHAKE128Context struct {
	ctx *sha3.State // Placeholder for internal state
}

// SHAKE256Context holds the state for SHAKE-256 incremental hashing.
type SHAKE256Context struct {
	ctx *sha3.State // Placeholder for internal state
}

// SHA2Callbacks defines the callback functions for SHA-2 operations.
type SHA2Callbacks struct {
	SHA256            func(output []byte, input []byte)
	SHA256IncInit     func(state *SHA256Context)
	SHA256IncFinalize func(out []byte, state *SHA256Context, in []byte)
	SHA384            func(output []byte, input []byte)
	SHA384IncInit     func(state *SHA384Context)
	SHA384IncFinalize func(out []byte, state *SHA384Context, in []byte)
	SHA512            func(output []byte, input []byte)
	SHA512IncInit     func(state *SHA512Context)
	SHA512IncFinalize func(out []byte, state *SHA512Context, in []byte)
}

// SHA3Callbacks defines the callback functions for SHA-3 operations.
type SHA3Callbacks struct {
	SHA3_256              func(output []byte, input []byte)
	SHA3_256_Inc_Init     func(state *SHA3_256Context)
	SHA3_256_Inc_Absorb   func(state *SHA3_256Context, input []byte)
	SHA3_256_Inc_Finalize func(output []byte, state *SHA3_256Context)
	SHA3_384              func(output []byte, input []byte)
	SHA3_512              func(output []byte, input []byte)
}

// Global variables to hold the current callbacks
var currentSHA2Callbacks *SHA2Callbacks
var currentSHA3Callbacks *SHA3Callbacks

// SetCallbacks sets the callback functions for SHA-2 operations.
func SetSHA2Callbacks(newCallbacks *SHA2Callbacks) {
	currentSHA2Callbacks = newCallbacks
}

// SetSHA3Callbacks sets the callback functions for SHA-3 operations.
func SetSHA3Callbacks(newCallbacks *SHA3Callbacks) {
	currentSHA3Callbacks = newCallbacks
}

// SHA256 computes the SHA-256 hash of the input.
func SHA256(output []byte, input []byte) {
	hash := sha256.Sum256(input)
	copy(output, hash[:])
}

// SHA512 computes the SHA-512 hash of the input.
func SHA512(output []byte, input []byte) {
	hash := sha512.Sum512(input)
	copy(output, hash[:])
}

// SHA3_256 computes the SHA3-256 hash of the input.
func SHA3_256(output []byte, input []byte) {
	hash := sha3.New256()
	hash.Write(input)
	copy(output, hash.Sum(nil))
}

// Incremental functions for SHA-256
func SHA256IncInit(state *SHA256Context) {
	state.dataLen = 0
}

func SHA256IncFinalize(out []byte, state *SHA256Context, in []byte) {
	SHA256(out, in)
}

// Incremental functions for SHA3-256
func SHA3_256_Inc_Init(state *SHA3_256Context) {
	state.ctx = sha3.New256()
}

func SHA3_256_Inc_Absorb(state *SHA3_256Context, input []byte) {
	if state.ctx == nil {
		return
	}
	state.ctx.Write(input)
}

func SHA3_256_Inc_Finalize(output []byte, state *SHA3_256Context) {
	if state.ctx == nil {
		return
	}
	copy(output, state.ctx.Sum(nil))
}

// Example usage
func RunExample() {
	// Set the SHA-2 callbacks
	SetSHA2Callbacks(&SHA2Callbacks{
		SHA256: SHA256,
		SHA512: SHA512,
	})

	// Set the SHA-3 callbacks
	SetSHA3Callbacks(&SHA3Callbacks{
		SHA3_256: SHA3_256,
	})

	// Example usage of SHA256
	output := make([]byte, 32) // SHA-256 produces a 32-byte hash
	input := []byte("Hello, World!")
	currentSHA2Callbacks.SHA256(output, input)
	fmt.Printf("SHA-256: %x\n", output)

	// Example usage of SHA3-256
	outputSHA3 := make([]byte, 32) // SHA3-256 produces a 32-byte hash
	currentSHA3Callbacks.SHA3_256(outputSHA3, input)
	fmt.Printf("SHA3-256: %x\n", outputSHA3)
}
