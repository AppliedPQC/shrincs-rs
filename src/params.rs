//! Constants of the SHRINCS draft.
//!
//! Every value here is either quoted from the draft's constant table or
//! derived from the defining equation beside it; `verify_parameter_consistency`
//! in `lib.rs` re-derives the derived ones and fails the test suite on drift.

/// Security parameter: every internal hash output is truncated to this width.
pub const N: usize = 16;

// --- stateful path: WOTS+C ------------------------------------------------
pub const WOTS_C_CHAIN_BITS: usize = 4;
pub const WOTS_C_CHAIN_COUNT: usize = 32;
pub const WOTS_C_CHAINS_SIZE: usize = WOTS_C_CHAIN_COUNT * N; // 512
/// `ceil(count * (2^bits - 1) / 2)`: the most likely index sum, and the target.
pub const WOTS_C_CONSTANT_SUM: usize =
    (WOTS_C_CHAIN_COUNT * ((1 << WOTS_C_CHAIN_BITS) - 1)).div_ceil(2); // 240

// --- stateful path: FXMSS -------------------------------------------------
/// The imaginary height of the FXMSS root. A leaf at depth `d` has height
/// `FXMSS_HEIGHT - d`, which is why the depth fits in one byte.
pub const FXMSS_HEIGHT: u8 = 255;
pub const FXMSS_SHAPE_UNBALANCED: u8 = 0;
pub const FXMSS_SHAPE_BALANCED: u8 = 1;

// --- stateless path: WOTS-TW ---------------------------------------------
pub const WOTS_TW_CHAIN_BITS: usize = 4;
pub const WOTS_TW_CHAIN_COUNT1: usize = 128_usize.div_ceil(WOTS_TW_CHAIN_BITS); // 32
pub const WOTS_TW_CHECKSUM_MAX: usize = WOTS_TW_CHAIN_COUNT1 * ((1 << WOTS_TW_CHAIN_BITS) - 1); // 480
pub const WOTS_TW_CHAIN_COUNT2: usize = 3;
pub const WOTS_TW_CHAIN_COUNT: usize = WOTS_TW_CHAIN_COUNT1 + WOTS_TW_CHAIN_COUNT2; // 35
pub const WOTS_TW_CHAINS_SIZE: usize = WOTS_TW_CHAIN_COUNT * N; // 560

// --- stateless path: the SLH-DSA parameter set SHRINCS chooses ------------
pub const SPHX_LAYER_COUNT: usize = 5; // d
pub const SPHX_XMSS_HEIGHT: usize = 9; // h'
pub const SPHX_FORS_HEIGHT: usize = 13; // a
pub const SPHX_FORS_COUNT: usize = 10; // k
/// `h - h'`, the bits of digest that pick a bottom-layer XMSS tree.
pub const SPHX_TREE_INDEX_BITS: usize = SPHX_XMSS_HEIGHT * (SPHX_LAYER_COUNT - 1); // 36
pub const FORS_DIGEST_SIZE: usize = (SPHX_FORS_COUNT * SPHX_FORS_HEIGHT).div_ceil(8); // 17
pub const FORS_SIGNATURE_SIZE: usize = SPHX_FORS_COUNT * (SPHX_FORS_HEIGHT + 1) * N; // 2240
pub const SPHX_XMSS_SIGNATURE_SIZE: usize = WOTS_TW_CHAINS_SIZE + SPHX_XMSS_HEIGHT * N; // 704
pub const HYPERTREE_SIGNATURE_SIZE: usize = SPHX_LAYER_COUNT * SPHX_XMSS_SIGNATURE_SIZE; // 3520
pub const SPHX_SIGNATURE_SIZE: usize = N + FORS_SIGNATURE_SIZE + HYPERTREE_SIGNATURE_SIZE; // 5776

// --- serialised sizes -----------------------------------------------------
pub const PUBKEY_SIZE: usize = 3 * N; // 48
pub const SECKEY_SIZE: usize = 5 * N + 2; // 82
pub const SEED_SIZE: usize = 3 * N; // 48
/// One leading discriminator byte on top of the SLH-DSA signature.
pub const SL_SIGNATURE_SIZE: usize = 1 + SPHX_SIGNATURE_SIZE; // 5777
pub const FXMSS_SIGNATURE_SIZE_MIN: usize = 2 + WOTS_C_CHAINS_SIZE + N; // 530
pub const FXMSS_SIGNATURE_SIZE_MAX: usize = 2 + WOTS_C_CHAINS_SIZE + 255 * N; // 4594
pub const SF_SIGNATURE_SIZE_MIN: usize = 1 + N + 1 + FXMSS_SIGNATURE_SIZE_MIN; // 548
pub const SF_SIGNATURE_SIZE_MAX: usize = 1 + N + 8 + FXMSS_SIGNATURE_SIZE_MAX; // 4619
