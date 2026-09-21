# One-time-key-reuse forgery (issue #59)

A runnable, end-to-end **existential forgery** against SHRINCS that follows from
the cache-rollback defect tracked as SHRINCS/shrincs-bip #59 and
AppliedPQC/pqc-research#38. It forges a signature on a **never-signed** message
that **both** the upstream Python reference verifier and this crate accept, using
only public data.

## Threat model

The signer re-uses one FXMSS leaf after a cache rollback --- a restored BDS
backup, a VM snapshot reset, an HSM recovered from a backup after a crash. The
attacker holds only the 48-byte public key and `k >= 2` honest signatures that a
rollback made land on the same leaf. **No secret key, and no interaction with the
signer** beyond collecting those signatures.

## Why it works

A WOTS+C signature opens each of the 32 hash chains at position `indexes[i]`, and
the verifier only ever walks a chain **forward**. Across `k` reuses the attacker
learns every chain at `m_i = min_k indexes[i]`, so it can open any constant-sum
target `c` with `c_i >= m_i`. `shrincs_verify` reads the randomiser `R` and the
2-byte grind counter **straight from the signature with no PRF check**, so the
attacker grinds `(R, counter)` offline until the induced target dominates `m`.
The Merkle authentication path is identical for a fixed leaf and is copied from a
reused signature. The constant-sum encoding only raises the grind cost; it does
not prevent the forgery.

## Run it

Requires Python 3.11+ (the reference `shrincs.py` uses byteorder-less
`int.to_bytes`/`from_bytes`, whose default was added in 3.11).

```sh
# from the crate root; clones shrincs-bip if --repo is omitted
./attack-59/reproduce.sh            # forge (k=4), then verify with shrincs-rs
python3 attack-59/forge.py --repo /path/to/shrincs-bip --reuse-k 3
python3 attack-59/forge.py && cargo test --test forgery -- --ignored   # Rust check on the generated fixtures
```

`forge.py` asserts the upstream `shrincs_verify` accepts the forgery and writes
`forged-job.json`; `tests/forgery.rs` and the `interop` example show this crate
accepts the identical bytes.

## Results (Intel Xeon, one core, BXMSS depth 6)

| reuses `k` | grind attempts | wall time | forged? (Python / Rust) |
|-----------:|---------------:|----------:|-------------------------|
| 4 | ~9.4 x 10^4 | ~1 s | yes / yes |
| 3 | 3.08 x 10^7 (≈2^24.9) | ~310 s | yes / yes |
| 2 | ~2^38 (analytic) | hours | (not run live) |

The grind count is randomised, so the k=4 figure varies run to run (10^5 order).
Controls (both implementations): a 1-bit-tampered forgery and the same signature
under a different message are **rejected**, so acceptance is not vacuous.

## What this shows

- The break is total: leaf reuse turns a one-time key into a universal forgery
  oracle for that leaf, at a cost that collapses with each extra reuse.
- It is **not** caught by any known-answer test: the failure is in the state
  lifecycle, not in the input/output map. Only a stateful rollback simulation
  surfaces it.
- A Python and a Rust implementation are affected identically, because the defect
  is in the specification's cache-management guidance, not in one codebase.

## Fix

The signing API must take the leaf from the authoritative, rollback-resistant
counter (never from a cache's own `state_ctr`); backup rules must be split by
cache type (position-dependent BDS state is not a deterministic function of the
key); and a signer should self-verify each signature before release.
