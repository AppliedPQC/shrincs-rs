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

/// The parameters of an SLH-DSA instantiation.
///
/// SHRINCS's stateless component is FIPS 205 under a non-standard set, which
/// is the draft's central reuse claim. Making the set a value rather than a
/// constant lets the same code be instantiated at the *standard* sets too, and
/// so be checked against NIST's own test vectors. See `tests/acvp.rs`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SlhParams {
    pub name: &'static str,
    /// Hypertree layers, `d`.
    pub d: usize,
    /// Height of one XMSS tree, `h'`.
    pub h_prime: usize,
    /// FORS tree height, `a`.
    pub a: usize,
    /// FORS tree count, `k`.
    pub k: usize,
}

impl SlhParams {
    /// Total hypertree height, `h = d * h'`.
    pub const fn h(&self) -> usize {
        self.d * self.h_prime
    }
    /// Digest bytes feeding FORS: `ceil(k*a/8)`.
    pub const fn fors_digest_size(&self) -> usize {
        (self.k * self.a).div_ceil(8)
    }
    /// Bits of digest that select a bottom-layer XMSS tree, `h - h'`.
    pub const fn tree_index_bits(&self) -> usize {
        self.h() - self.h_prime
    }
    /// The message digest length `m`, in bytes.
    pub const fn m(&self) -> usize {
        self.fors_digest_size() + self.tree_index_bits().div_ceil(8) + self.h_prime.div_ceil(8)
    }
    pub const fn fors_signature_size(&self) -> usize {
        self.k * (self.a + 1) * N
    }
    pub const fn xmss_signature_size(&self) -> usize {
        WOTS_TW_CHAINS_SIZE + self.h_prime * N
    }
    pub const fn signature_size(&self) -> usize {
        N + self.fors_signature_size() + self.d * self.xmss_signature_size()
    }
    /// Signature budget, `2^h`.
    pub const fn budget_log2(&self) -> usize {
        self.h()
    }
}

/// The set SHRINCS chooses for its fallback: 2^40 signatures, 5,776 bytes.
pub const SHRINCS_SL: SlhParams = SlhParams {
    name: "SHRINCS-SL",
    d: SPHX_LAYER_COUNT,
    h_prime: SPHX_XMSS_HEIGHT,
    a: SPHX_FORS_HEIGHT,
    k: SPHX_FORS_COUNT,
};

/// SLH-DSA-SHA2-128s, FIPS 205 Table 2. Not used by SHRINCS; present so that
/// the shared machinery can be checked against NIST's vectors.
pub const SLH_DSA_SHA2_128S: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-128s",
    d: 7,
    h_prime: 9,
    a: 12,
    k: 14,
};

/// SLH-DSA-SHA2-128f, FIPS 205 Table 2.
pub const SLH_DSA_SHA2_128F: SlhParams = SlhParams {
    name: "SLH-DSA-SHA2-128f",
    d: 22,
    h_prime: 3,
    a: 6,
    k: 33,
};
