// OQS-GO
// Aaron Stovall

package oqs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"unsafe"
)

// Version Constants
const (
	OQS_VERSION_TEXT         = "0.12.0-rc1"
	OQS_VERSION_MAJOR        = 0
	OQS_VERSION_MINOR        = 12
	OQS_VERSION_PATCH        = 0
	OQS_VERSION_PRE_RELEASE  = "-rc1"
	OQS_COMPILE_BUILD_TARGET = "AMD64-Windows-10.0.26100"
	OQS_DIST_BUILD           = 1
	OQS_DIST_X86_64_BUILD    = 1
	ARCH_X86_64              = 1
	BUILD_SHARED_LIBS        = 1
	OQS_OPT_TARGET           = "auto"
	OQS_LIBJADE_BUILD        = 0
)

// KEM (Key Encapsulation Mechanism) Constants
const (
	OQS_ENABLE_KEM_FRODOKEM                  = 1
	OQS_ENABLE_KEM_frodokem_640_aes          = 1
	OQS_ENABLE_KEM_frodokem_640_shake        = 1
	OQS_ENABLE_KEM_frodokem_976_aes          = 1
	OQS_ENABLE_KEM_frodokem_976_shake        = 1
	OQS_ENABLE_KEM_frodokem_1344_aes         = 1
	OQS_ENABLE_KEM_frodokem_1344_shake       = 1
	OQS_ENABLE_KEM_NTRUPRIME                 = 1
	OQS_ENABLE_KEM_ntruprime_sntrup761       = 1
	OQS_ENABLE_KEM_CLASSIC_MCELIECE          = 1
	OQS_ENABLE_KEM_classic_mceliece_348864   = 1
	OQS_ENABLE_KEM_classic_mceliece_348864f  = 1
	OQS_ENABLE_KEM_classic_mceliece_460896   = 1
	OQS_ENABLE_KEM_classic_mceliece_460896f  = 1
	OQS_ENABLE_KEM_classic_mceliece_6688128  = 1
	OQS_ENABLE_KEM_classic_mceliece_6688128f = 1
	OQS_ENABLE_KEM_classic_mceliece_6960119  = 1
	OQS_ENABLE_KEM_classic_mceliece_6960119f = 1
	OQS_ENABLE_KEM_classic_mceliece_8192128  = 1
	OQS_ENABLE_KEM_classic_mceliece_8192128f = 1
	OQS_ENABLE_KEM_HQC                       = 1
	OQS_ENABLE_KEM_hqc_128                   = 1
	OQS_ENABLE_KEM_hqc_192                   = 1
	OQS_ENABLE_KEM_hqc_256                   = 1
	OQS_ENABLE_KEM_KYBER                     = 1
	OQS_ENABLE_KEM_kyber_512                 = 1
	OQS_ENABLE_KEM_kyber_768                 = 1
	OQS_ENABLE_KEM_kyber_1024                = 1
	OQS_ENABLE_KEM_ML_KEM                    = 1
	OQS_ENABLE_KEM_ml_kem_512                = 1
	OQS_ENABLE_KEM_ml_kem_768                = 1
	OQS_ENABLE_KEM_ml_kem_1024               = 1
)

// Signature Constants
const (
	OQS_ENABLE_SIG_DILITHIUM                 = 1
	OQS_ENABLE_SIG_dilithium_2               = 1
	OQS_ENABLE_SIG_dilithium_3               = 1
	OQS_ENABLE_SIG_dilithium_5               = 1
	OQS_ENABLE_SIG_ML_DSA                    = 1
	OQS_ENABLE_SIG_ml_dsa_44                 = 1
	OQS_ENABLE_SIG_ml_dsa_65                 = 1
	OQS_ENABLE_SIG_ml_dsa_87                 = 1
	OQS_ENABLE_SIG_FALCON                    = 1
	OQS_ENABLE_SIG_falcon_512                = 1
	OQS_ENABLE_SIG_falcon_1024               = 1
	OQS_ENABLE_SIG_falcon_padded_512         = 1
	OQS_ENABLE_SIG_falcon_padded_1024        = 1
	OQS_ENABLE_SIG_SPHINCS                   = 1
	OQS_ENABLE_SIG_sphincs_sha2_128f_simple  = 1
	OQS_ENABLE_SIG_sphincs_sha2_128s_simple  = 1
	OQS_ENABLE_SIG_sphincs_sha2_192f_simple  = 1
	OQS_ENABLE_SIG_sphincs_sha2_192s_simple  = 1
	OQS_ENABLE_SIG_sphincs_sha2_256f_simple  = 1
	OQS_ENABLE_SIG_sphincs_sha2_256s_simple  = 1
	OQS_ENABLE_SIG_sphincs_shake_128f_simple = 1
	OQS_ENABLE_SIG_sphincs_shake_128s_simple = 1
	OQS_ENABLE_SIG_sphincs_shake_192f_simple = 1
	OQS_ENABLE_SIG_sphincs_shake_192s_simple = 1
	OQS_ENABLE_SIG_sphincs_shake_256f_simple = 1
	OQS_ENABLE_SIG_sphincs_shake_256s_simple = 1
	OQS_ENABLE_SIG_MAYO                      = 1
	OQS_ENABLE_SIG_mayo_1                    = 1
	OQS_ENABLE_SIG_mayo_2                    = 1
	OQS_ENABLE_SIG_mayo_3                    = 1
	OQS_ENABLE_SIG_mayo_5                    = 1
	OQS_ENABLE_SIG_CROSS                     = 1
	OQS_ENABLE_SIG_cross_rsdp_128_balanced   = 1
	OQS_ENABLE_SIG_cross_rsdp_128_fast       = 1
	OQS_ENABLE_SIG_cross_rsdp_128_small      = 1
	OQS_ENABLE_SIG_cross_rsdp_192_balanced   = 1
	OQS_ENABLE_SIG_cross_rsdp_192_fast       = 1
	OQS_ENABLE_SIG_cross_rsdp_192_small      = 1
	OQS_ENABLE_SIG_cross_rsdp_256_balanced   = 1
	OQS_ENABLE_SIG_cross_rsdp_256_fast       = 1
	OQS_ENABLE_SIG_cross_rsdp_256_small      = 1
)

// OQS_STATUS represents return values from functions.
type OQS_STATUS int

const (
	OQS_ERROR                      OQS_STATUS = -1 // Indicates that some undefined error occurred.
	OQS_SUCCESS                    OQS_STATUS = 0  // Indicates successful return from function.
	OQS_EXTERNAL_LIB_ERROR_OPENSSL OQS_STATUS = 50 // Indicates failures in external libraries (e.g., OpenSSL).
)

// OQS_CPU_EXT represents CPU runtime detection flags.
type OQS_CPU_EXT int

const (
	OQS_CPU_EXT_INIT OQS_CPU_EXT = iota
	OQS_CPU_EXT_ADX
	OQS_CPU_EXT_AES
	OQS_CPU_EXT_AVX
	OQS_CPU_EXT_AVX2
	OQS_CPU_EXT_AVX512
	OQS_CPU_EXT_BMI1
	OQS_CPU_EXT_BMI2
	OQS_CPU_EXT_PCLMULQDQ
	OQS_CPU_EXT_VPCLMULQDQ
	OQS_CPU_EXT_POPCNT
	OQS_CPU_EXT_SSE
	OQS_CPU_EXT_SSE2
	OQS_CPU_EXT_SSE3
	OQS_CPU_EXT_ARM_AES
	OQS_CPU_EXT_ARM_SHA2
	OQS_CPU_EXT_ARM_SHA3
	OQS_CPU_EXT_ARM_NEON
	OQS_CPU_EXT_COUNT
)

// Memory Management Functions
func OQS_MEM_malloc(size int) unsafe.Pointer {
	return unsafe.Pointer(&make([]byte, size)[0])
}

func OQS_MEM_calloc(numElements, elementSize int) unsafe.Pointer {
	return unsafe.Pointer(&make([]byte, numElements*elementSize)[0])
}

func OQS_MEM_strdup(str string) *string {
	dup := str
	return &dup
}

func OQS_MEM_secure_free(ptr unsafe.Pointer, len int) {
	if ptr != nil {
		OQS_MEM_cleanse(ptr, len)
		// Freeing memory is handled by Go's garbage collector
	}
}

func OQS_MEM_insecure_free(ptr unsafe.Pointer) {
	// Freeing memory is handled by Go's garbage collector
}

// Utility Functions
func OQS_EXIT_IF_NULLPTR(x unsafe.Pointer, loc string) {
	if x == nil {
		fmt.Printf("Unexpected NULL returned from %s API. Exiting.\n", loc)
		runtime.Goexit()
	}
}

// CPU Extension Functions
func OQS_CPU_has_extension(ext OQS_CPU_EXT) int {
	switch ext {
	case OQS_CPU_EXT_AES:
		return checkAES()
	case OQS_CPU_EXT_AVX:
		return checkAVX()
	case OQS_CPU_EXT_AVX2:
		return checkAVX2()
	default:
		return 0 // Unsupported extension
	}
}

// Check Functions for CPU Extensions
func checkAES() int {
	if isAESAvailable() {
		return 1 // AES is supported
	}
	return 0 // AES is not supported
}

func checkAVX() int {
	if isAVXAvailable() {
		return 1 // AVX is supported
	}
	return 0 // AVX is not supported
}

func checkAVX2() int {
	if isAVX2Available() {
		return 1 // AVX2 is supported
	}
	return 0 // AVX2 is not supported
}

// cpuid calls the assembly function to get CPU feature information.
func cpuid(leaf uint32) (eax, ebx, ecx, edx uint32) {
	// Call the assembly function
	// The return values are stored in eax, ebx, ecx, edx
	// This is a placeholder for the actual assembly call
	return
}

// isAESAvailable checks if the CPU supports AES instructions.
func isAESAvailable() bool {
	_, _, ecx, _ := cpuid(1)      // Leaf 1 for basic feature information
	return (ecx & (1 << 25)) != 0 // Check the AES bit (bit 25)
}

// isAVXAvailable checks if the CPU supports AVX instructions.
func isAVXAvailable() bool {
	_, _, ecx, _ := cpuid(1)      // Leaf 1 for basic feature information
	return (ecx & (1 << 28)) != 0 // Check the AVX bit (bit 28)
}

// isAVX2Available checks if the CPU supports AVX2 instructions.
func isAVX2Available() bool {
	_, ebx, _, _ := cpuid(7)     // Leaf 7 for extended feature information
	return (ebx & (1 << 5)) != 0 // Check the AVX2 bit (bit 5 of EBX)
}

// Global variables to hold KEMs and signature algorithms
var kemList []KEM
var signatureList []Signature

// KEM represents a Key Encapsulation Mechanism
type KEM struct {
	Name       string
	Parameters map[string]interface{}
}

// Signature represents a signature algorithm
type Signature struct {
	Name       string
	Parameters map[string]interface{}
}

// Initialize the random number generator
var secureRandomGenerator *rand.Rand

// initializeRandomGenerator initializes the random number generator.
func initializeRandomGenerator() error {
	seed := make([]byte, 8) // 8 bytes for a 64-bit seed
	if _, err := rand.Read(seed); err != nil {
		return errors.New("failed to read from secure random source: " + err.Error())
	}
	seedInt64 := int64(binary.BigEndian.Uint64(seed))
	secureRandomGenerator = rand.New(rand.NewSource(seedInt64))
	return nil
}

// GenerateRandomBytes generates a slice of random bytes of the specified length.
func GenerateRandomBytes(length int) ([]byte, error) {
	if secureRandomGenerator == nil {
		return nil, errors.New("random generator not initialized")
	}
	randomBytes := make([]byte, length)
	_, err := secureRandomGenerator.Read(randomBytes)
	if err != nil {
		return nil, errors.New("failed to generate random bytes: " + err.Error())
	}
	return randomBytes, nil
}

// Example usage of the random generator
func main() {
	// Initialize the random generator
	if err := initializeRandomGenerator(); err != nil {
		fmt.Println("Error initializing random generator:", err)
		return
	}

	// Generate 16 random bytes
	randomData, err := GenerateRandomBytes(16)
	if err != nil {
		fmt.Println("Error generating random bytes:", err)
		return
	}

	fmt.Printf("Generated random bytes: %x\n", randomData)
}
