//! The hash suite is a parameter, and swapping it changes the scheme.
//!
//! These tests exist to make that concrete rather than to be read as
//! encouragement: only `Shrincs256` is SHRINCS.

use shrincs::{hash::Sha256, params::*, Shrincs, Shrincs256, Structure};

#[test]
fn the_default_entry_points_are_the_specified_scheme() {
    assert_eq!(Shrincs256::HASH, "SHA-256");
    let seed = [1u8; SEED_SIZE];
    let (sk_free, pk_free) = shrincs::keygen(&seed, Structure::balanced(2));
    let (sk_expl, pk_expl) = Shrincs::<Sha256>::keygen(&seed, Structure::balanced(2));
    assert_eq!(sk_free, sk_expl, "the free functions must be Shrincs256");
    assert_eq!(pk_free, pk_expl);
}

#[cfg(feature = "blake3")]
mod blake3_suite {
    use super::*;
    use shrincs::hash::Blake3;
    type Alt = Shrincs<Blake3>;

    #[test]
    fn the_construction_works_over_a_different_primitive() {
        let seed = [2u8; SEED_SIZE];
        let structure = Structure::unbalanced(3);
        let (sk, pk) = Alt::keygen(&seed, structure);
        assert_eq!(Alt::HASH, "BLAKE3");

        for c in 0..structure.budget() {
            let sig = Alt::sign(b"over blake3", b"", &sk, Some(c), None).unwrap();
            assert!(Alt::verify(b"over blake3", &sig, b"", &pk));
            assert!(!Alt::verify(b"tampered", &sig, b"", &pk));
        }
        let fb = Alt::sign(b"over blake3", b"", &sk, None, None).unwrap();
        assert_eq!(
            fb.len(),
            SL_SIGNATURE_SIZE,
            "sizes are structural, not primitive-dependent"
        );
        assert!(Alt::verify(b"over blake3", &fb, b"", &pk));
    }

    #[test]
    fn a_different_suite_is_a_different_scheme() {
        let seed = [2u8; SEED_SIZE];
        let structure = Structure::balanced(2);
        let (sk_a, pk_a) = Shrincs256::keygen(&seed, structure);
        let (sk_b, pk_b) = Alt::keygen(&seed, structure);

        // Same seed, same shape, different keys: the suite reaches key derivation.
        assert_ne!(pk_a, pk_b, "public keys must differ between suites");
        assert_ne!(sk_a[48..], sk_b[48..], "the derived roots must differ");

        // Signatures do not carry across, in either direction.
        let sig_a = Shrincs256::sign(b"m", b"", &sk_a, Some(0), None).unwrap();
        let sig_b = Alt::sign(b"m", b"", &sk_b, Some(0), None).unwrap();
        assert_ne!(sig_a, sig_b);
        assert!(
            !Alt::verify(b"m", &sig_a, b"", &pk_a),
            "SHA-256 signature under BLAKE3"
        );
        assert!(
            !Shrincs256::verify(b"m", &sig_b, b"", &pk_b),
            "BLAKE3 signature under SHA-256"
        );
    }
}
