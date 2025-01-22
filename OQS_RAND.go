// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/rand"
	"errors"
	"sync"
)

// Algorithm identifiers for random number generation.
const (
	OQS_RAND_alg_system  = "system"
	OQS_RAND_alg_openssl = "OpenSSL" // Placeholder for future implementation
	OQS_RAND_alg_custom  = "custom"  // Identifier for custom RNG algorithms
)

// RandomAlgorithm is a function type for custom random number generators.
type RandomAlgorithm func([]byte) (int, error)

// currentAlgorithm holds the currently selected random number generator.
var (
	currentAlgorithm RandomAlgorithm = defaultRandomAlgorithm
	algorithmMutex   sync.RWMutex    // Ensures thread-safe access to currentAlgorithm
)

// defaultRandomAlgorithm uses the crypto/rand package to generate random bytes.
func defaultRandomAlgorithm(b []byte) (int, error) {
	n, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// SwitchAlgorithm switches the random number generator to the specified algorithm.
func SwitchAlgorithm(algorithm string, customFunc ...RandomAlgorithm) OQS_STATUS {
	algorithmMutex.Lock()
	defer algorithmMutex.Unlock()

	switch algorithm {
	case OQS_RAND_alg_system:
		currentAlgorithm = defaultRandomAlgorithm
		return OQS_SUCCESS
	case OQS_RAND_alg_openssl:
		// Placeholder for OpenSSL-based RNG (to be implemented)
		return OQS_ERROR
	case OQS_RAND_alg_custom:
		if len(customFunc) == 0 {
			return OQS_ERROR // Custom algorithm requires a function to be provided
		}
		currentAlgorithm = customFunc[0]
		return OQS_SUCCESS
	default:
		return OQS_ERROR // Unsupported algorithm
	}
}

// CustomAlgorithm sets a custom random number generator function.
func CustomAlgorithm(algorithmFunc RandomAlgorithm) error {
	if algorithmFunc == nil {
		return errors.New("custom RNG function cannot be nil")
	}
	return SwitchAlgorithm(OQS_RAND_alg_custom, algorithmFunc)
}

// RandomBytes fills the given slice with the requested number of (pseudo)random bytes.
func RandomBytes(randomArray []byte) error {
	if len(randomArray) == 0 {
		return errors.New("buffer is empty") // Ensure the buffer is not empty
	}
	algorithmMutex.RLock()
	defer algorithmMutex.RUnlock()

	_, err := currentAlgorithm(randomArray)
	return err
}

// ValidateRandomness validates the quality of the generated random bytes.
func ValidateRandomness(randomArray []byte) bool {
	if len(randomArray) == 0 {
		return false
	}
	seen := make(map[byte]bool)
	for _, b := range randomArray {
		seen[b] = true
		if len(seen) > len(randomArray)/2 {
			return true // High entropy detected
		}
	}
	return false // Low entropy detected
}

// Example Usage
func RANDExampleUsage() {
	randomBytes := make([]byte, 32) // Generate 32 random bytes

	if err := RandomBytes(randomBytes); err != nil {
		panic("Random byte generation failed: " + err.Error())
	}

	if !ValidateRandomness(randomBytes) {
		panic("Random bytes failed entropy validation")
	}

	println("Generated random bytes:", randomBytes)
}

// Utility to ensure thread-safety and extensibility for additional RNG algorithms.
