// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// Context structure for SHA operations (SHA-224, SHA-256, etc.)
type SHAContext struct {
	Algorithm string
	State     interface{}
	DataLen   uint64
	Data      []byte
}

// SHA2Functions encapsulates SHA-2 specific operations.
type SHA2Functions struct {
	Hash   func(output []byte, input []byte)
	HMAC   func(key []byte, data []byte, output []byte) error
	Init   func(ctx *SHAContext)
	Update func(ctx *SHAContext, input []byte)
	Finish func(ctx *SHAContext, output []byte)
}

// SHA3Functions encapsulates SHA-3 specific operations.
type SHA3Functions struct {
	Hash   func(output []byte, input []byte)
	HMAC   func(key []byte, data []byte, output []byte) error
	Init   func(ctx *SHAContext)
	Update func(ctx *SHAContext, input []byte)
	Finish func(ctx *SHAContext, output []byte)
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

// HMACSHA256 computes the HMAC for SHA-256.
func HMACSHA256(key []byte, data []byte, output []byte) error {
	if len(output) < sha256.Size {
		return errors.New("output buffer is too small")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	copy(output, mac.Sum(nil))
	return nil
}

// HMACSHA3_256 computes the HMAC for SHA3-256.
func HMACSHA3_256(key []byte, data []byte, output []byte) error {
	h := sha3.New256()
	mac := hmac.New(func() hash.Hash { return h }, key)
	mac.Write(data)
	copy(output, mac.Sum(nil))
	return nil
}

// SHA Context Initialization
func SHA256Init(ctx *SHAContext) {
	ctx.State = sha256.New()
	ctx.Data = make([]byte, 0)
	ctx.Algorithm = "SHA-256"
}

func SHA3_256Init(ctx *SHAContext) {
	ctx.State = sha3.New256()
	ctx.Data = make([]byte, 0)
	ctx.Algorithm = "SHA3-256"
}

// Incremental updates for SHA
func SHAUpdate(ctx *SHAContext, input []byte) {
	if ctx.State != nil {
		if h, ok := ctx.State.(hash.Hash); ok {
			h.Write(input)
			ctx.DataLen += uint64(len(input))
		}
	}
}

// Finish SHA computation
func SHAFinish(ctx *SHAContext, output []byte) {
	if ctx.State != nil {
		if h, ok := ctx.State.(hash.Hash); ok {
			copy(output, h.Sum(nil))
		}
	}
}

// Example Usage
func SHAExampleUsage() {
	// Standard Hash Usage
	output := make([]byte, sha256.Size)
	SHA256(output, []byte("Hello, World!"))
	fmt.Printf("SHA-256: %x\n", output)

	// HMAC Usage
	hmacOutput := make([]byte, sha256.Size)
	key := []byte("secret-key")
	data := []byte("message")
	if err := HMACSHA256(key, data, hmacOutput); err != nil {
		fmt.Println("HMAC Error:", err)
	} else {
		fmt.Printf("HMAC-SHA-256: %x\n", hmacOutput)
	}

	// Incremental Hash Usage
	ctx := &SHAContext{}
	SHA256Init(ctx)
	SHAUpdate(ctx, []byte("Hello"))
	SHAUpdate(ctx, []byte(", World!"))
	SHAFinish(ctx, output)
	fmt.Printf("Incremental SHA-256: %x\n", output)
}
