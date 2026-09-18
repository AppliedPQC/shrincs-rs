//! SHRINCS: a semi-stateful hash-based signature scheme.
//!
//! A reference implementation of the draft BIP posted to bitcoin-dev on
//! 27 August 2026, <https://github.com/SHRINCS/shrincs-bip>.
//!
//! **Not for production.** The draft says so of itself, and so does this: the
//! scheme has no security proof yet, and this code has had no audit. It is
//! written to be read beside the specification.
//!
//! # The shape of the scheme
//!
//! One 48-byte public key carries two signing paths.
//!
//! * The **stateful** path signs with a WOTS+C leaf of an FXMSS tree, from 548
//!   bytes. It needs a counter that must never repeat.
//! * The **stateless** fallback is SLH-DSA under a non-standard parameter set,
//!   a fixed 5,777 bytes, and needs no state at all.
//!
//! Either verifies against the same key, so losing the counter costs signature
//! size rather than funds. The two are cross-bound: each path's message digest
//! carries the other path's root, so neither component can be lifted out and
//! used alone.
//!
//! ```
//! use shrincs::{keygen, sign, verify, Structure};
//! let seed = [7u8; 48];
//! let (sk, pk) = keygen(&seed, Structure::balanced(3).unwrap()).unwrap();
//!
//! // stateful, with the counter the caller is responsible for advancing
//! let sig = sign(b"hello", b"", &sk, Some(0), None).unwrap();
//! assert_eq!(sig.len(), 580);
//! assert!(verify(b"hello", &sig, b"", &pk));
//!
//! // no counter available: the fallback signs instead, and still verifies
//! let fb = sign(b"hello", b"", &sk, None, None).unwrap();
//! assert_eq!(fb.len(), 5777);
//! assert!(verify(b"hello", &fb, b"", &pk));
//! ```

pub mod adrs;
pub mod fxmss;
pub mod hash;
pub mod params;
pub mod stateless;
pub mod wots;

use adrs::Adrs;
use hash::HashSuite;
use params::*;

/// The deepest balanced tree accepted. At this depth every quantity on the
/// stateful path, leaf index, counter and budget alike, fits a `u64`. At depth
/// 64 the budget `2^64` would not, so a `u64` counter could reach only
/// `2^64 - 1` of the leaves; the draft leaves that invariant emergent
/// (SHRINCS/shrincs-bip#58) and this crate makes it a rule.
pub const BXMSS_MAX_DEPTH: u8 = 63;

/// The default ceiling on stateful-tree work, counted in WOTS+C leaves.
///
/// Key generation computes every leaf of the stateful tree, and each stateful
/// signature recomputes the authentication path, which touches all of them
/// again: a balanced tree of depth `d` costs `2^d` either way. `2^16` is about
/// 24 seconds on the machine the README measures. The ceiling exists so that a
/// structure from an untrusted or corrupted source fails at once instead of
/// running for days. Raise it with [`Shrincs::keygen_with_limit`] and
/// [`Shrincs::sign_with_limit`] for a deeper tree you mean to pay for.
pub const DEFAULT_MAX_LEAVES: u64 = 1 << 16;

/// The shape of the stateful tree, chosen once at key generation.
///
/// Only well-formed shapes have a value of this type: there is none for a
/// balanced tree deeper than [`BXMSS_MAX_DEPTH`], nor for a shape byte the
/// draft does not define.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Structure(pub(crate) [u8; 2]);

impl Structure {
    /// A left-leaning tree. Budget `depth + 1`; the early signatures are the
    /// smallest the scheme can produce and they grow as the key is reused.
    /// Every depth is valid, since its leaf indexes are only ever 0 and 1.
    pub fn unbalanced(depth: u8) -> Self {
        Structure([FXMSS_SHAPE_UNBALANCED, depth])
    }
    /// A balanced tree. Budget `2^depth`, every signature the same size.
    /// `None` above [`BXMSS_MAX_DEPTH`].
    pub fn balanced(depth: u8) -> Option<Self> {
        (depth <= BXMSS_MAX_DEPTH).then_some(Structure([FXMSS_SHAPE_BALANCED, depth]))
    }
    /// Reads the two structure bytes a secret key carries. `None` for a shape
    /// byte the draft does not define, or a balanced tree too deep to accept.
    pub fn from_bytes(bytes: [u8; 2]) -> Option<Self> {
        match bytes[0] {
            FXMSS_SHAPE_UNBALANCED => Some(Self::unbalanced(bytes[1])),
            FXMSS_SHAPE_BALANCED => Self::balanced(bytes[1]),
            _ => None,
        }
    }
    pub fn to_bytes(self) -> [u8; 2] {
        self.0
    }
    pub fn depth(&self) -> u8 {
        self.0[1]
    }
    /// How many WOTS+C leaves the tree has. Key generation computes all of
    /// them, and so, near enough, does each stateful signature; this is the
    /// work either one costs.
    pub fn leaves(&self) -> u64 {
        match self.0[0] {
            FXMSS_SHAPE_UNBALANCED => self.0[1] as u64 + 1,
            // Balanced, and no deeper than BXMSS_MAX_DEPTH by construction.
            _ => 1u64 << self.0[1],
        }
    }
    /// How many stateful signatures this shape allows before the fallback
    /// takes over. Every leaf counts except in a depth-zero tree, whose one
    /// leaf would sit at height 255, the byte that marks a fallback signature.
    pub fn budget(&self) -> u64 {
        if self.0[1] == 0 {
            0
        } else {
            self.leaves()
        }
    }
}

pub type SecretKey = [u8; SECKEY_SIZE];
pub type PublicKey = [u8; PUBKEY_SIZE];

/// The scheme, over a choice of hash suite.
///
/// [`Shrincs256`] is the one the draft specifies. Any other instantiation is a
/// different scheme: it will not interoperate, the draft's security argument
/// does not carry over, and the known-answer tests do not apply.
pub struct Shrincs<S: HashSuite>(core::marker::PhantomData<S>);

/// SHRINCS as specified: SHA-256 throughout.
pub type Shrincs256 = Shrincs<hash::Sha256>;

impl<S: HashSuite> Shrincs<S> {
    /// Which hash suite this instantiation uses, for error messages and tests.
    pub const HASH: &'static str = S::NAME;

    /// Produces `pk_seed || sl_root || sf_root`. Truncating the public key's
    /// last 16 bytes leaves a valid SLH-DSA public key for the fallback.
    ///
    /// `None` when the stateful tree has more than [`DEFAULT_MAX_LEAVES`]
    /// leaves; see [`Self::keygen_with_limit`].
    pub fn keygen(seed: &[u8; SEED_SIZE], structure: Structure) -> Option<(SecretKey, PublicKey)> {
        Self::keygen_with_limit(seed, structure, DEFAULT_MAX_LEAVES)
    }

    /// [`Self::keygen`] under an explicit ceiling on the stateful tree's
    /// leaves. The ceiling is checked before any hashing, so a refusal costs
    /// nothing.
    pub fn keygen_with_limit(
        seed: &[u8; SEED_SIZE],
        structure: Structure,
        max_leaves: u64,
    ) -> Option<(SecretKey, PublicKey)> {
        if structure.leaves() > max_leaves {
            return None;
        }
        let (sk_seed, sk_prf, pk_seed) = (&seed[0..16], &seed[16..32], &seed[32..48]);
        let mut adrs = Adrs::new();
        adrs.set_layer((SPHX_LAYER_COUNT - 1) as u8);
        let sl_root = stateless::xmss_node::<S>(sk_seed, 0, SHRINCS_SL.h_prime, pk_seed, &mut adrs);
        let sf_root = fxmss::fxmss_node::<S>(
            sk_seed,
            0,
            FXMSS_HEIGHT,
            pk_seed,
            structure.0,
            &mut Adrs::new(),
        );

        let mut sk = [0u8; SECKEY_SIZE];
        sk[0..16].copy_from_slice(sk_seed);
        sk[16..32].copy_from_slice(sk_prf);
        sk[32..48].copy_from_slice(pk_seed);
        sk[48..64].copy_from_slice(&sl_root);
        sk[64..66].copy_from_slice(&structure.0);
        sk[66..82].copy_from_slice(&sf_root);

        let mut pk = [0u8; PUBKEY_SIZE];
        pk[0..16].copy_from_slice(pk_seed);
        pk[16..32].copy_from_slice(&sl_root);
        pk[32..48].copy_from_slice(&sf_root);
        Some((sk, pk))
    }

    /// Signs with the stateful path when `state_ctr` names an unused leaf, and
    /// with the stateless fallback otherwise. Exhausting the budget is not an
    /// error: it takes the same branch as having no counter at all.
    ///
    /// `None` for a context of 256 bytes or more, for a secret key whose
    /// structure bytes name no valid shape, and for a stateful signature over
    /// a tree with more than [`DEFAULT_MAX_LEAVES`] leaves; see
    /// [`Self::sign_with_limit`].
    ///
    /// **The caller owns the counter.** Signing twice under one value hands an
    /// observer of both signatures the ability to forge. Persist it before
    /// releasing the signature, never restore it from a backup, and never sign
    /// concurrently with it.
    pub fn sign(
        message: &[u8],
        ctx: &[u8],
        sk: &SecretKey,
        state_ctr: Option<u64>,
        opt_rand: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        Self::sign_with_limit(message, ctx, sk, state_ctr, opt_rand, DEFAULT_MAX_LEAVES)
    }

    /// [`Self::sign`] under an explicit ceiling on the stateful tree's leaves,
    /// for a key made by [`Self::keygen_with_limit`] above the default. The
    /// ceiling binds only the stateful path; the fallback never touches the
    /// tree.
    pub fn sign_with_limit(
        message: &[u8],
        ctx: &[u8],
        sk: &SecretKey,
        state_ctr: Option<u64>,
        opt_rand: Option<&[u8]>,
        max_leaves: u64,
    ) -> Option<Vec<u8>> {
        if ctx.len() >= 256 {
            return None;
        }
        let (sk_seed, sk_prf, pk_seed) = (&sk[0..16], &sk[16..32], &sk[32..48]);
        let (sl_root, sf_root) = (&sk[48..64], &sk[66..82]);
        // `keygen` writes only well-formed structures, so a key carrying any
        // other is corrupt or crafted. It is refused rather than walked: an
        // over-deep balanced tree would run for years.
        let structure = Structure::from_bytes([sk[64], sk[65]])?;

        let leaf = state_ctr.and_then(|c| fxmss::leaf_select(structure, c));
        let Some((leaf_index, leaf_height)) = leaf else {
            let mut out = Vec::with_capacity(SL_SIGNATURE_SIZE);
            out.push(FXMSS_HEIGHT);
            out.extend_from_slice(&stateless::slh_dsa_sign::<S>(
                &[sf_root, message],
                ctx,
                sk_seed,
                sk_prf,
                pk_seed,
                sl_root,
                opt_rand,
                &SHRINCS_SL,
            ));
            return Some(out);
        };
        if structure.leaves() > max_leaves {
            return None;
        }

        let prefix = [0u8, ctx.len() as u8];
        let bound: [&[u8]; 4] = [&prefix, ctx, sl_root, message];
        let mut adrs = Adrs::new();
        adrs.set_node_height(leaf_height).set_node_index(leaf_index);
        let r = S::prf_msg_sf(sk_prf, pk_seed, &adrs, &bound);
        let digest = S::h_msg_sf(&r, pk_seed, sf_root, &adrs, &bound);
        let fxmss_sig = fxmss::fxmss_sign::<S>(
            &digest,
            sk_seed,
            leaf_index,
            leaf_height,
            pk_seed,
            structure.0,
        )?;

        let leaf_depth = (FXMSS_HEIGHT - leaf_height) as usize;
        let index_len = leaf_depth.min(64).div_ceil(8);
        let mut out = Vec::with_capacity(1 + N + index_len + fxmss_sig.len());
        out.push(leaf_height);
        out.extend_from_slice(&r);
        out.extend_from_slice(&leaf_index.to_be_bytes()[8 - index_len..]);
        out.extend_from_slice(&fxmss_sig);
        Some(out)
    }

    /// Accepts a signature from either path. The first byte is the
    /// discriminator: 255 is the fallback, anything below it is the leaf
    /// height of a stateful signature. Depth zero cannot sign, which is what
    /// frees 255 as a tag.
    pub fn verify(message: &[u8], sig: &[u8], ctx: &[u8], pk: &PublicKey) -> bool {
        if ctx.len() >= 256 || sig.is_empty() {
            return false;
        }
        let (pk_seed, sl_root, sf_root) = (&pk[0..16], &pk[16..32], &pk[32..48]);
        let indicator = sig[0];

        if indicator == FXMSS_HEIGHT {
            return stateless::slh_dsa_verify::<S>(
                &[sf_root, message],
                &sig[1..],
                ctx,
                pk_seed,
                sl_root,
                &SHRINCS_SL,
            );
        }
        if !(SF_SIGNATURE_SIZE_MIN..=SF_SIGNATURE_SIZE_MAX).contains(&sig.len()) {
            return false;
        }
        let leaf_height = indicator;
        let leaf_depth = (FXMSS_HEIGHT - leaf_height) as u32;
        let index_len = (leaf_depth as usize).min(64).div_ceil(8);
        if sig.len() < 1 + N + index_len {
            return false;
        }
        let r = &sig[1..1 + N];
        let mut idx = [0u8; 8];
        idx[8 - index_len..].copy_from_slice(&sig[1 + N..1 + N + index_len]);
        let leaf_index = u64::from_be_bytes(idx);
        if !fxmss::index_fits(leaf_index, leaf_depth) {
            return false;
        }

        let prefix = [0u8, ctx.len() as u8];
        let bound: [&[u8]; 4] = [&prefix, ctx, sl_root, message];
        let mut adrs = Adrs::new();
        adrs.set_node_height(leaf_height).set_node_index(leaf_index);
        let digest = S::h_msg_sf(r, pk_seed, sf_root, &adrs, &bound);

        match fxmss::fxmss_pubkey_from_sig::<S>(
            leaf_index,
            leaf_height,
            &sig[1 + N + index_len..],
            &digest,
            pk_seed,
        ) {
            Some(root) => root == sf_root,
            None => false,
        }
    }
}

// The scheme as specified. These are the entry points to reach for; anything
// generic over a suite is an experiment, not SHRINCS.

/// Key generation for SHRINCS as specified. `None` above
/// [`DEFAULT_MAX_LEAVES`]; see [`Shrincs::keygen_with_limit`].
pub fn keygen(seed: &[u8; SEED_SIZE], structure: Structure) -> Option<(SecretKey, PublicKey)> {
    Shrincs256::keygen(seed, structure)
}

/// Signing for SHRINCS as specified. See [`Shrincs::sign`] for the counter rules.
pub fn sign(
    message: &[u8],
    ctx: &[u8],
    sk: &SecretKey,
    state_ctr: Option<u64>,
    opt_rand: Option<&[u8]>,
) -> Option<Vec<u8>> {
    Shrincs256::sign(message, ctx, sk, state_ctr, opt_rand)
}

/// Verification for SHRINCS as specified.
pub fn verify(message: &[u8], sig: &[u8], ctx: &[u8], pk: &PublicKey) -> bool {
    Shrincs256::verify(message, sig, ctx, pk)
}

/// Re-derives every size the draft states, from the defining equations.
/// A test calls this, so a mistyped constant fails the suite rather than
/// silently producing a scheme that is not SHRINCS.
pub fn verify_parameter_consistency() -> Result<(), String> {
    let check = |name: &str, got: usize, want: usize| {
        if got == want {
            Ok(())
        } else {
            Err(format!("{name}: computed {got}, draft says {want}"))
        }
    };
    check("WOTS_C_CONSTANT_SUM", WOTS_C_CONSTANT_SUM, 240)?;
    check("WOTS_C_CHAINS_SIZE", WOTS_C_CHAINS_SIZE, 512)?;
    check("WOTS_TW_CHAIN_COUNT", WOTS_TW_CHAIN_COUNT, 35)?;
    check("WOTS_TW_CHAINS_SIZE", WOTS_TW_CHAINS_SIZE, 560)?;
    check("WOTS_TW_CHECKSUM_MAX", WOTS_TW_CHECKSUM_MAX, 480)?;
    check("FORS_DIGEST_SIZE", FORS_DIGEST_SIZE, 17)?;
    check("FORS_SIGNATURE_SIZE", FORS_SIGNATURE_SIZE, 2240)?;
    check("SPHX_XMSS_SIGNATURE_SIZE", SPHX_XMSS_SIGNATURE_SIZE, 704)?;
    check("HYPERTREE_SIGNATURE_SIZE", HYPERTREE_SIGNATURE_SIZE, 3520)?;
    check("SPHX_SIGNATURE_SIZE", SPHX_SIGNATURE_SIZE, 5776)?;
    check("SPHX_TREE_INDEX_BITS", SPHX_TREE_INDEX_BITS, 36)?;
    check("SL_SIGNATURE_SIZE", SL_SIGNATURE_SIZE, 5777)?;
    check("SF_SIGNATURE_SIZE_MIN", SF_SIGNATURE_SIZE_MIN, 548)?;
    check("SF_SIGNATURE_SIZE_MAX", SF_SIGNATURE_SIZE_MAX, 4619)?;
    check("FXMSS_SIGNATURE_SIZE_MIN", FXMSS_SIGNATURE_SIZE_MIN, 530)?;
    check("FXMSS_SIGNATURE_SIZE_MAX", FXMSS_SIGNATURE_SIZE_MAX, 4594)?;
    // The verifier's chain work is the same constant for every message; that
    // is the property the constant-sum encoding exists to buy.
    let total = WOTS_C_CHAIN_COUNT * ((1 << WOTS_C_CHAIN_BITS) - 1);
    check("verifier chain steps", total - WOTS_C_CONSTANT_SUM, 240)?;
    Ok(())
}
