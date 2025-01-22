// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"
)

// Version Information
const (
	OQS_VERSION_TEXT         = "1.0.0"
	OQS_VERSION_MAJOR        = 1
	OQS_VERSION_MINOR        = 0
	OQS_VERSION_PATCH        = 0
	OQS_COMPILE_BUILD_TARGET = "AMD64-Windows"
	ARCH_X86_64              = 1
	BUILD_SHARED_LIBS        = 1
)

// OQS_STATUS represents function return values.
type OQS_STATUS int

const (
	OQS_ERROR   OQS_STATUS = -1 // Generic error.
	OQS_SUCCESS OQS_STATUS = 0  // Success.
)

// Thread-safe random number generator management.
var (
	rngLock               sync.Mutex
	secureRandomGenerator *rand.Rand
)

// Initialize the random generator.
func initializeRandomGenerator() error {
	rngLock.Lock()
	defer rngLock.Unlock()

	if secureRandomGenerator != nil {
		return nil // Already initialized
	}

	seed := make([]byte, 8) // 8 bytes for a 64-bit seed
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("failed to initialize random generator: %w", err)
	}

	seedInt64 := int64(binary.BigEndian.Uint64(seed))
	secureRandomGenerator = rand.New(rand.NewSource(seedInt64))
	return nil
}

// GenerateRandomBytes generates a specified number of random bytes.
func GenerateRandomBytes(length int) ([]byte, error) {
	rngLock.Lock()
	defer rngLock.Unlock()

	if secureRandomGenerator == nil {
		if err := initializeRandomGenerator(); err != nil {
			return nil, err
		}
	}

	randomBytes := make([]byte, length)
	_, err := secureRandomGenerator.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return randomBytes, nil
}

// CPU Extension Detection.
func OQS_CPU_has_extension(ext string) bool {
	supportedExtensions := map[string]bool{
		"AES": true, "AVX": true, "AVX2": true, // Add as necessary
	}

	return supportedExtensions[ext]
}

// Memory Management.
func OQS_MEM_malloc(size int) unsafe.Pointer {
	if size <= 0 {
		return nil
	}
	return unsafe.Pointer(&make([]byte, size)[0])
}

func OQS_MEM_secure_free(ptr unsafe.Pointer, size int) {
	if ptr != nil {
		OQS_MEM_cleanse(ptr, size)
	}
}

func OQS_MEM_cleanse(ptr unsafe.Pointer, size int) {
	if ptr == nil || size <= 0 {
		return
	}
	// Implement memory overwriting to clear sensitive data
	mem := (*[1 << 30]byte)(ptr)[:size:size] // Limit slice size
	for i := range mem {
		mem[i] = 0
	}
}

// Example Usage.
func MainExampleUsage() {
	if err := initializeRandomGenerator(); err != nil {
		fmt.Println("Initialization error:", err)
		return
	}

	randomData, err := GenerateRandomBytes(16)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
		return
	}

	fmt.Printf("Random bytes: %x\n", randomData)

	fmt.Println("CPU supports AES:", OQS_CPU_has_extension("AES"))
}
