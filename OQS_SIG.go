// OQS-GO
// Aaron Stovall

package oqs

import (
	"errors"
)

// Constants for public key, secret key, and signature lengths for various signature schemes
const (
	// Cross RSDP
	OQS_SIG_cross_rsdp_128_balanced_length_public_key = 77
	OQS_SIG_cross_rsdp_128_balanced_length_secret_key = 32
	OQS_SIG_cross_rsdp_128_balanced_length_signature   = 12912

	OQS_SIG_cross_rsdp_128_fast_length_public_key = 77
	OQS_SIG_cross_rsdp_128_fast_length_secret_key = 32
	OQS_SIG_cross_rsdp_128_fast_length_signature   = 19152

	OQS_SIG_cross_rsdp_128_small_length_public_key = 77
	OQS_SIG_cross_rsdp_128_small_length_secret_key = 32
	OQS_SIG_cross_rsdp_128_small_length_signature   = 10080

	OQS_SIG_cross_rsdp_192_balanced_length_public_key = 115
	OQS_SIG_cross_rsdp_192_balanced_length_secret_key = 48
	OQS_SIG_cross_rsdp_192_balanced_length_signature   = 28222

	OQS_SIG_cross_rsdp_192_fast_length_public_key = 115
	OQS_SIG_cross_rsdp_192_fast_length_secret_key = 48
	OQS_SIG_cross_rsdp_192_fast_length_signature   = 42682

	OQS_SIG_cross_rsdp_192_small_length_public_key = 115
	OQS_SIG_cross_rsdp_192_small_length_secret_key = 48
	OQS_SIG_cross_rsdp_192_small_length_signature   = 23642

	OQS_SIG_cross_rsdp_256_balanced_length_public_key = 153
	OQS_SIG_cross_rsdp_256_balanced_length_secret_key = 64
	OQS_SIG_cross_rsdp_256_balanced_length_signature   = 51056

	OQS_SIG_cross_rsdp_256_fast_length_public_key = 153
	OQS_SIG_cross_rsdp_256_fast_length_secret_key = 64
	OQS_SIG_cross_rsdp_256_fast_length_signature   = 76298

	OQS_SIG_cross_rsdp_256_small_length_public_key = 153
	OQS_SIG_cross_rsdp_256_small_length_secret_key = 64
	OQS_SIG_cross_rsdp_256_small_length_signature   = 43592

	OQS_SIG_cross_rsdpg_128_balanced_length_public_key = 54
	OQS_SIG_cross_rsdpg_128_balanced_length_secret_key = 32
	OQS_SIG_cross_rsdpg_128_balanced_length_signature   = 9236

	OQS_SIG_cross_rsdpg_128_fast_length_public_key = 54
	OQS_SIG_cross_rsdpg_128_fast_length_secret_key = 32
	OQS_SIG_cross_rsdpg_128_fast_length_signature   = 12472

	OQS_SIG_cross_rsdpg_128_small_length_public_key = 54
	OQS_SIG_cross_rsdpg_128_small_length_secret_key = 32
	OQS_SIG_cross_rsdpg_128_small_length_signature   = 7956

	OQS_SIG_cross_rsdpg_192_balanced_length_public_key = 83
	OQS_SIG_cross_rsdpg_192_balanced_length_secret_key = 48
	OQS_SIG_cross_rsdpg_192_balanced_length_signature   = 23380

	OQS_SIG_cross_rsdpg_192_fast_length_public_key = 83
	OQS_SIG_cross_rsdpg_192_fast_length_secret_key = 48
	OQS_SIG_cross_rsdpg_192_fast_length_signature   = 27404

	OQS_SIG_cross_rsdpg_192_small_length_public_key = 83
	OQS_SIG_cross_rsdpg_192_small_length_secret_key = 48
	OQS_SIG_cross_rsdpg_192_small_length_signature   = 18188 
)

// Constants for Dilithium signature schemes
const (
	OQS_SIG_dilithium_2_length_public_key = 1312
	OQS_SIG_dilithium_2_length_secret_key = 2528
	OQS_SIG_dilithium_2_length_signature  = 2420

	OQS_SIG_dilithium_3_length_public_key = 1952
	OQS_SIG_dilithium_3_length_secret_key = 4000
	OQS_SIG_dilithium_3_length_signature  = 3293

	OQS_SIG_dilithium_5_length_public_key = 2592
	OQS_SIG_dilithium_5_length_secret_key = 4864
	OQS_SIG_dilithium_5_length_signature  = 4595
)

// Constants for Falcon signature schemes
const (
	OQS_SIG_falcon_512_length_public_key = 897
	OQS_SIG_falcon_512_length_secret_key = 1281
	OQS_SIG_falcon_512_length_signature  = 752

	OQS_SIG_falcon_1024_length_public_key = 1793
	OQS_SIG_falcon_1024_length_secret_key = 2305
	OQS_SIG_falcon_1024_length_signature  = 1462

	OQS_SIG_falcon_padded_512_length_public_key = 897
	OQS_SIG_falcon_padded_512_length_secret_key = 1281
	OQS_SIG_falcon_padded_512_length_signature  = 666

	OQS_SIG_falcon_padded_1024_length_public_key = 1793
	OQS_SIG_falcon_padded_1024_length_secret_key = 2305
	OQS_SIG_falcon_padded_1024_length_signature  = 1280
)

// Constants for Mayo signature schemes
const (
	OQS_SIG_mayo_1_length_public_key  = 1168
	OQS_SIG_mayo_1_length_secret_key  = 24
	OQS_SIG_mayo_1_length_signature    = 321

	OQS_SIG_mayo_2_length_public_key  = 5488
	OQS_SIG_mayo_2_length_secret_key  = 24
	OQS_SIG_mayo_2_length_signature    = 180

	OQS_SIG_mayo_3_length_public_key  = 2656
	OQS_SIG_mayo_3_length_secret_key  = 32
	OQS_SIG_mayo_3_length_signature    = 577

	OQS_SIG_mayo_5_length_public_key  = 5008
	OQS_SIG_mayo_5_length_secret_key  = 40
	OQS_SIG_mayo_5_length_signature    = 838
)

// Constants for ML-DSA signature schemes
const (
	OQS_SIG_ml_dsa_44_length_public_key = 1312
	OQS_SIG_ml_dsa_44_length_secret_key = 2560
	OQS_SIG_ml_dsa_44_length_signature  = 2420

	OQS_SIG_ml_dsa_65_length_public_key = 1952
	OQS_SIG_ml_dsa_65_length_secret_key = 4032
	OQS_SIG_ml_dsa_65_length_signature  = 3309

	// Constants for ML-DSA signature schemes
const (
	OQS_SIG_ml_dsa_87_length_public_key = 2592
	OQS_SIG_ml_dsa_87_length_secret_key = 4864
	OQS_SIG_ml_dsa_87_length_signature  = 4595

	OQS_SIG_ml_dsa_128_length_public_key = 3584
	OQS_SIG_ml_dsa_128_length_secret_key = 6144
	OQS_SIG_ml_dsa_128_length_signature  = 6144
)

// Constants for SPHINCS+ signature schemes
const (
	OQS_SIG_sphincs_haraka_128f_length_public_key = 1296
	OQS_SIG_sphincs_haraka_128f_length_secret_key = 1280
	OQS_SIG_sphincs_haraka_128f_length_signature  = 8192

	OQS_SIG_sphincs_haraka_128s_length_public_key = 1296
	OQS_SIG_sphincs_haraka_128s_length_secret_key = 1280
	OQS_SIG_sphincs_haraka_128s_length_signature  = 8192

	OQS_SIG_sphincs_haraka_192f_length_public_key = 1920
	OQS_SIG_sphincs_haraka_192f_length_secret_key = 1920
	OQS_SIG_sphincs_haraka_192f_length_signature  = 8192

	OQS_SIG_sphincs_haraka_192s_length_public_key = 1920
	OQS_SIG_sphincs_haraka_192s_length_secret_key = 1920
	OQS_SIG_sphincs_haraka_192s_length_signature  = 8192

	OQS_SIG_sphincs_haraka_256f_length_public_key = 2560
	OQS_SIG_sphincs_haraka_256f_length_secret_key = 2560
	OQS_SIG_sphincs_haraka_256f_length_signature  = 8192

	OQS_SIG_sphincs_haraka_256s_length_public_key = 2560
	OQS_SIG_sphincs_haraka_256s_length_secret_key = 2560
	OQS_SIG_sphincs_haraka_256s_length_signature  = 8192
)

// Constants for XMSS signature schemes
const (
	OQS_SIG_xmss_length_public_key = 32
	OQS_SIG_xmss_length_secret_key = 32
	OQS_SIG_xmss_length_signature  = 64

	OQS_SIG_xmssmt_length_public_key = 32
	OQS_SIG_xmssmt_length_secret_key = 32
	OQS_SIG_xmssmt_length_signature  = 64
)