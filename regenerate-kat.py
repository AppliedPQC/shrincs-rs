#!/usr/bin/env python3
"""Regenerate tests/kat.json from the draft's own reference implementation.

The vectors this crate is tested against come from upstream, not from this
crate, so they check it against the specification rather than against itself.
This script fetches that implementation and runs it.

    ./regenerate-kat.py [--repo DIR]

With no argument it clones https://github.com/SHRINCS/shrincs-bip into a
temporary directory. The upstream commit is recorded in the output, so a
regenerated file that differs shows both that and the changed vectors.
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile

UPSTREAM = "https://github.com/SHRINCS/shrincs-bip"

def load(repo):
    sys.path.insert(0, os.path.join(repo, "impl"))
    import shrincs
    commit = subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
    return shrincs, commit

def build(R, commit):
    h = lambda b: b.hex()
    seed = bytes(range(48))
    pk_seed = seed[32:48]

    adrs = bytearray(22)
    adrs[9] = R.SF_WOTS_C_GRIND
    digest = hashlib.sha256(b"component").digest()
    counter, indexes = R.wots_c_grind_to_constant_sum(pk_seed, digest, adrs)
    assert sum(indexes) == R.WOTS_C_CONSTANT_SUM

    kat = {
        "_source": UPSTREAM,
        "_commit": commit,
        "seed": h(seed),
        "components": {
            "sha256_trunc16": h(hashlib.sha256(b"abc").digest()[:16]),
            "grind_digest": h(digest),
            "grind_counter": counter,
            "grind_indexes": indexes,
            "H_grind": h(R.H_grind(pk_seed, adrs, digest, counter)),
            "base_2b": R.base_2b(R.H_grind(pk_seed, adrs, digest, counter), 4, 32),
        },
        "cases": [],
    }

    # The first two are small enough to keep the suite quick; the second two are
    # the shapes upstream's own impl/test.py exercises.
    for shape, depth in ((0, 4), (1, 3), (1, 4), (0, 16)):
        sf = bytes([shape, depth])
        sk, pk = R.shrincs_keygen(seed, sf)
        budget = depth + 1 if shape == R.FXMSS_SHAPE_UNBALANCED else 2 ** depth
        stateful = []
        for c in range(budget):
            msg = ("SHRINCS KAT %d" % c).encode()
            sig = R.shrincs_sign(msg, b"", sk, c, None)
            assert R.shrincs_verify(msg, sig, b"", pk)
            stateful.append({"ctr": c, "msg": h(msg), "sig": h(sig)})
        msg = b"stateless fallback"
        sl = R.shrincs_sign(msg, b"", sk, None, None)
        assert R.shrincs_verify(msg, sl, b"", pk)
        kat["cases"].append({
            "shape": shape, "depth": depth, "sf_structure": h(sf),
            "seckey": h(sk), "pubkey": h(pk),
            "stateful": stateful,
            "stateless": {"msg": h(msg), "sig": h(sl)},
        })
        print("  shape %d depth %-2d : %d stateful + 1 stateless" % (shape, depth, budget))
    return kat

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="an existing checkout of the draft repository")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        repo = args.repo
        if not repo:
            repo = os.path.join(tmp, "shrincs-bip")
            print("cloning %s" % UPSTREAM)
            subprocess.check_call(["git", "clone", "-q", UPSTREAM, repo])
        R, commit = load(repo)
        print("upstream commit %s" % commit)
        kat = build(R, commit)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests", "kat.json")
    with open(out, "w") as fh:
        json.dump(kat, fh, indent=1)
    print("wrote %s" % out)

if __name__ == "__main__":
    main()
