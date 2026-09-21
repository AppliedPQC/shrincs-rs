//! The two limits on the stateful tree, and the malformed keys they turn away.
//!
//! The first is a rule about representation: a balanced tree is at most 63
//! deep, so every stateful quantity fits a `u64` (SHRINCS/shrincs-bip#58). The
//! second is a ceiling on work, so that a structure nobody can afford fails at
//! once. None of these tests builds a large tree; each refusal is immediate,
//! and a test that hangs is a test that failed.

use shrincs::fxmss::leaf_select;
use shrincs::{keygen, sign, verify, Shrincs256, Structure, BXMSS_MAX_DEPTH, DEFAULT_MAX_LEAVES};
use std::time::Instant;

#[test]
fn balanced_depth_is_capped_at_63() {
    assert_eq!(BXMSS_MAX_DEPTH, 63);
    assert!(Structure::balanced(63).is_some());
    for d in [64u8, 65, 100, 255] {
        assert!(Structure::balanced(d).is_none(), "depth {d} accepted");
    }
}

#[test]
fn from_bytes_admits_only_what_keygen_can_make() {
    assert_eq!(
        Structure::from_bytes([0, 255]),
        Some(Structure::unbalanced(255))
    );
    assert_eq!(Structure::from_bytes([1, 63]), Structure::balanced(63));
    for bad in [[1u8, 64], [1, 255], [2, 3], [0xff, 0]] {
        assert!(Structure::from_bytes(bad).is_none(), "{bad:?} accepted");
    }
}

#[test]
fn budget_counts_exactly_the_usable_leaves() {
    assert_eq!(Structure::balanced(63).unwrap().budget(), 1 << 63);
    assert_eq!(Structure::balanced(10).unwrap().budget(), 1024);
    assert_eq!(Structure::unbalanced(5).budget(), 6);
    // A depth-zero tree's one leaf would sit at height 255, the fallback's tag.
    assert_eq!(Structure::balanced(0).unwrap().budget(), 0);
    assert_eq!(Structure::unbalanced(0).budget(), 0);
}

/// Before the cap, depth 64 counted its budget as `u64::MAX` and so could
/// never select leaf `2^64 - 1`, which the draft's reference signs. With the
/// cap, every leaf the budget counts is selectable and none beyond it.
#[test]
fn every_counted_leaf_is_selectable_and_none_beyond() {
    for d in [1u8, 5, 16, 62, 63] {
        let s = Structure::balanced(d).unwrap();
        assert!(
            leaf_select(s, s.budget() - 1).is_some(),
            "depth {d}: last leaf"
        );
        assert!(
            leaf_select(s, s.budget()).is_none(),
            "depth {d}: past the end"
        );
    }
    let deepest = Structure::balanced(63).unwrap();
    assert!(leaf_select(deepest, u64::MAX).is_none());
}

#[test]
fn keygen_refuses_over_the_ceiling_before_hashing() {
    assert_eq!(DEFAULT_MAX_LEAVES, 1 << 16);
    let seed = [1u8; 48];
    let t = Instant::now();
    assert!(keygen(&seed, Structure::balanced(17).unwrap()).is_none());
    assert!(keygen(&seed, Structure::balanced(63).unwrap()).is_none());
    // The stateless root alone takes a few hundred milliseconds, so a refusal
    // this fast came before it, not after.
    assert!(
        t.elapsed().as_millis() < 100,
        "refusal took {:?}",
        t.elapsed()
    );
}

#[test]
fn the_ceiling_moves_in_both_directions() {
    let seed = [2u8; 48];
    let s = Structure::balanced(5).unwrap(); // 32 leaves
    assert!(Shrincs256::keygen_with_limit(&seed, s, 16).is_none());
    let (sk, pk) = Shrincs256::keygen_with_limit(&seed, s, 32).unwrap();

    // The same key signs statefully only under a ceiling that admits it...
    assert!(Shrincs256::sign_with_limit(b"m", b"", &sk, Some(0), None, 16).is_none());
    let sig = Shrincs256::sign_with_limit(b"m", b"", &sk, Some(0), None, 32).unwrap();
    assert!(verify(b"m", &sig, b"", &pk));

    // ...while the fallback never touches the tree, so no ceiling binds it.
    let fb = Shrincs256::sign_with_limit(b"m", b"", &sk, None, None, 16).unwrap();
    assert_eq!(fb.len(), 5777);
    assert!(verify(b"m", &fb, b"", &pk));
}

/// A key `keygen` could not have written is refused outright, on both paths.
/// Before this, a balanced depth of 100 in the key sent `sign` into a tree it
/// would never finish. An undefined shape instead fell through to the
/// fallback, as the draft's reference still does; refusing it too is a
/// deliberate departure, since no conforming `keygen` can produce such a key.
#[test]
fn sign_refuses_a_key_with_a_malformed_structure() {
    let (mut sk, _) = keygen(&[3u8; 48], Structure::balanced(2).unwrap()).unwrap();
    for bad in [[1u8, 64], [1, 100], [1, 255], [2, 3]] {
        sk[64..66].copy_from_slice(&bad);
        assert!(sign(b"m", b"", &sk, Some(0), None).is_none(), "{bad:?}");
        assert!(
            sign(b"m", b"", &sk, None, None).is_none(),
            "{bad:?} on the fallback"
        );
    }
}
