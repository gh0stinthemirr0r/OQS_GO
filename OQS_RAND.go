// OQS-GO
// Aaron Stovall

package oqs

import (
	"crypto/rand"
	"errors"
)

// Algorithm identifiers for random number generation.
const (
	OQS_RAND_alg_system  = "system"
	OQS_RAND_alg_openssl = "OpenSSL" // Placeholder for future implementation
)

// RandomAlgorithm is a function type for custom random number generators.
type RandomAlgorithm func([]byte) (int, error)

// currentAlgorithm holds the currently selected random number generator.
var currentAlgorithm RandomAlgorithm = defaultRandomAlgorithm

// defaultRandomAlgorithm uses the crypto/rand package to generate random bytes.
func defaultRandomAlgorithm(b []byte) (int, error) {
	n, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// SwitchAlgorithm switches the random number generator to the specified algorithm.
func SwitchAlgorithm(algorithm string) OQS_STATUS {
	switch algorithm {
	case OQS_RAND_alg_system:
		currentAlgorithm = defaultRandomAlgorithm
		return OQS_SUCCESS
	// Additional algorithms can be added here in the future
	default:
		return OQS_ERROR // Unsupported algorithm
	}
}

// CustomAlgorithm sets a custom random number generator function.
func CustomAlgorithm(algorithmFunc RandomAlgorithm) {
	currentAlgorithm = algorithmFunc
}

// RandomBytes fills the given slice with the requested number of (pseudo)random bytes.
func RandomBytes(randomArray []byte) error {
	if len(randomArray) == 0 {
		return errors.New("buffer is empty") // Ensure the buffer is not empty
	}
	_, err := currentAlgorithm(randomArray)
	return err
}
