//! The hash layer, and the trait that lets it be swapped.
//!
//! # What the draft fixes, and what this abstracts
//!
//! SHRINCS specifies SHA-256 and nothing else, deliberately: it is the hash
//! Bitcoin consensus already has, and reusing it keeps the analysis and the
//! hardware acceleration that come with it. Everything below is therefore
//! structured so that [`Sha256`] reproduces the draft byte for byte.
//!
//! The trait exists because the *shape* of the construction does not depend on
//! SHA-256. Every tweakable hash is
//!
//! ```text
//! digest(pk_seed || 0^pad || ADRS || M)[..16]
//! ```
//!
//! and only `digest`, a keyed mode, and the padding width change between
//! primitives. A suite supplies those three; the nine named functions of the
//! draft are then derived once, here, and shared.
//!
//! # A warning about substitution
//!
//! **A scheme instantiated with any suite other than [`Sha256`] is not
//! SHRINCS.** It will not interoperate, the draft's security argument does not
//! transfer to it, and the known-answer tests do not apply. The type parameter
//! is there for experiment and comparison. [`crate::Shrincs256`] is the scheme
//! the draft describes, and the free functions at the crate root are aliases
//! for it, so the specified behaviour is what you get by default.

use crate::adrs::Adrs;
use crate::params::N;

pub type Hash = [u8; N];

/// The primitives a hash suite must supply. Everything else is derived.
pub trait HashSuite {
    /// Named in error messages and test output, so a mismatch is legible.
    const NAME: &'static str;

    /// Zero bytes placed after `pk_seed` so that the seed fills a whole
    /// compression input and its state can be precomputed once per key.
    ///
    /// SHA-256 uses 48, bringing the 16-byte seed to one 64-byte block. A
    /// primitive with no block structure worth exploiting can use 0; that
    /// changes the encoding, and so changes the scheme, which is the point of
    /// making it explicit.
    const SEED_PAD: usize;

    /// The unkeyed digest, over the concatenation of `parts`.
    fn digest(parts: &[&[u8]]) -> [u8; 32];

    /// The keyed digest. SHA-256 uses HMAC because the draft says so; a
    /// primitive with a native keyed mode should use that instead.
    fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32];

    // --- derived: the nine named functions of the draft -------------------

    /// The tweakable hash. `F`, `H`, `T_sl`, `T_sf` and `T_k` are all this
    /// function, separated only by the address handed to them.
    fn t(pk_seed: &[u8], adrs: &Adrs, m: &[&[u8]]) -> Hash {
        const ZEROS: [u8; 64] = [0u8; 64];
        let mut parts: Vec<&[u8]> = Vec::with_capacity(3 + m.len());
        parts.push(pk_seed);
        parts.push(&ZEROS[..Self::SEED_PAD]);
        parts.push(adrs.as_bytes());
        parts.extend_from_slice(m);
        truncate(Self::digest(&parts))
    }

    /// One step of a Winternitz chain.
    fn f(pk_seed: &[u8], adrs: &Adrs, m: &[u8]) -> Hash {
        Self::t(pk_seed, adrs, &[m])
    }

    /// Combines two Merkle children.
    fn h(pk_seed: &[u8], adrs: &Adrs, left: &[u8], right: &[u8]) -> Hash {
        Self::t(pk_seed, adrs, &[left, right])
    }

    /// Reads only the first ten address bytes, so the whole input fits a
    /// single further compression. Grinding runs this up to 2^16 times per
    /// signature, which is why it is the one function that does not take the
    /// full address.
    fn h_grind(pk_seed: &[u8], adrs: &Adrs, digest: &[u8], counter: u16) -> Hash {
        const ZEROS: [u8; 64] = [0u8; 64];
        truncate(Self::digest(&[
            pk_seed,
            &ZEROS[..Self::SEED_PAD],
            &adrs.as_bytes()[..10],
            digest,
            &[0u8; 4],
            &counter.to_be_bytes(),
        ]))
    }

    /// Derives a chain or FORS secret. Consumes the whole 22-byte address,
    /// which is how an FXMSS tree shape reaches every secret it owns.
    fn prf(pk_seed: &[u8], sk_seed: &[u8], adrs: &Adrs) -> Hash {
        const ZEROS: [u8; 64] = [0u8; 64];
        truncate(Self::digest(&[
            pk_seed,
            &ZEROS[..Self::SEED_PAD],
            adrs.as_bytes(),
            sk_seed,
        ]))
    }

    /// Message randomiser for the stateless path.
    fn prf_msg_sl(sk_prf: &[u8], opt_rand: &[u8], m: &[&[u8]]) -> Hash {
        let mut parts: Vec<&[u8]> = Vec::with_capacity(1 + m.len());
        parts.push(opt_rand);
        parts.extend_from_slice(m);
        truncate(Self::mac(sk_prf, &parts))
    }

    /// Message randomiser for the stateful path. The key is padded with 0xFF
    /// so that it cannot coincide with the stateless key above.
    fn prf_msg_sf(sk_prf: &[u8], pk_seed: &[u8], adrs: &Adrs, m: &[&[u8]]) -> Hash {
        let mut key = [0xFFu8; 64];
        key[..sk_prf.len()].copy_from_slice(sk_prf);
        let mut parts: Vec<&[u8]> = Vec::with_capacity(2 + m.len());
        parts.push(pk_seed);
        parts.push(&adrs.as_bytes()[..9]);
        parts.extend_from_slice(m);
        truncate(Self::mac(&key, &parts))
    }

    /// Stateless message digest, MGF1 over the digest of the inputs, to
    /// `out_len` bytes.
    ///
    /// It takes its own root as a parameter; the caller passes the *stateful*
    /// root inside `m`. That asymmetry is the cross-binding, and it is why
    /// neither component can be used alone.
    ///
    /// The draft writes this as a single further digest with four zero bytes
    /// appended, which is exactly MGF1's first block, so for any `out_len` up
    /// to 32 the two coincide. Writing it as MGF1 is what lets the standard
    /// FIPS 205 parameter sets run through the same code: SLH-DSA-SHA2-128f
    /// needs m = 34, and so a second block.
    fn h_msg_sl(r: &[u8], pk_seed: &[u8], sl_root: &[u8], m: &[&[u8]], out_len: usize) -> Vec<u8> {
        let mut inner: Vec<&[u8]> = vec![r, pk_seed, sl_root];
        inner.extend_from_slice(m);
        let inner = Self::digest(&inner);
        let mut out = Vec::with_capacity(out_len.next_multiple_of(32));
        let mut counter: u32 = 0;
        while out.len() < out_len {
            out.extend_from_slice(&Self::digest(&[r, pk_seed, &inner, &counter.to_be_bytes()]));
            counter += 1;
        }
        out.truncate(out_len);
        out
    }

    /// Stateful message digest, binding the leaf position through the first
    /// nine address bytes, and the stateless root through `m`.
    fn h_msg_sf(r: &[u8], pk_seed: &[u8], sf_root: &[u8], adrs: &Adrs, m: &[&[u8]]) -> [u8; 32] {
        let a9 = &adrs.as_bytes()[..9];
        let mut inner: Vec<&[u8]> = vec![r, pk_seed, sf_root, a9];
        inner.extend_from_slice(m);
        let inner = Self::digest(&inner);
        Self::digest(&[r, pk_seed, &inner, a9])
    }
}

fn truncate(d: [u8; 32]) -> Hash {
    let mut out = [0u8; N];
    out.copy_from_slice(&d[..N]);
    out
}

/// SHA-256: the suite the draft specifies, and the only one that is SHRINCS.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256;

impl HashSuite for Sha256 {
    const NAME: &'static str = "SHA-256";
    const SEED_PAD: usize = 48;

    fn digest(parts: &[&[u8]]) -> [u8; 32] {
        use sha2::{Digest, Sha256 as S};
        let mut h = S::new();
        for p in parts {
            h.update(p);
        }
        h.finalize().into()
    }

    /// HMAC-SHA256, as the draft writes it out.
    fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        debug_assert!(key.len() <= 64);
        let mut padded = [0u8; 64];
        padded[..key.len()].copy_from_slice(key);
        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= padded[i];
            opad[i] ^= padded[i];
        }
        let mut inner: Vec<&[u8]> = Vec::with_capacity(1 + parts.len());
        inner.push(&ipad);
        inner.extend_from_slice(parts);
        let inner = Self::digest(&inner);
        Self::digest(&[&opad, &inner])
    }
}

/// BLAKE3. **Not SHRINCS**, and not interoperable with it.
///
/// Provided so the cost of the construction can be measured against a
/// different primitive. Two choices here are this crate's, not the draft's:
/// `SEED_PAD` is zero, because BLAKE3 has no 64-byte block boundary to align
/// a cached seed to, and `mac` uses BLAKE3's native keyed mode over a digest
/// of the key rather than HMAC.
#[cfg(feature = "blake3")]
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3;

#[cfg(feature = "blake3")]
impl HashSuite for Blake3 {
    const NAME: &'static str = "BLAKE3";
    const SEED_PAD: usize = 0;

    fn digest(parts: &[&[u8]]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for p in parts {
            h.update(p);
        }
        *h.finalize().as_bytes()
    }

    fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let k = Self::digest(&[key]);
        let mut h = blake3::Hasher::new_keyed(&k);
        for p in parts {
            h.update(p);
        }
        *h.finalize().as_bytes()
    }
}

/// Reads `out_len` big-endian fields of `b` bits each from `x`.
/// Independent of the hash suite.
pub fn base_2b(x: &[u8], b: usize, out_len: usize) -> Vec<u32> {
    debug_assert!(x.len() >= (out_len * b).div_ceil(8));
    let mut out = Vec::with_capacity(out_len);
    let (mut j, mut acc, mut bits) = (0usize, 0u64, 0usize);
    for _ in 0..out_len {
        while bits < b {
            acc = (acc << 8) | x[j] as u64;
            j += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((acc >> bits) & ((1u64 << b) - 1)) as u32);
    }
    out
}
