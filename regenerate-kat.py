#!/usr/bin/env python3
"""Regenerate tests/kat.json from the draft's own reference implementation.

The vectors this crate is tested against come from upstream, not from this
crate, so they check it against the specification rather than against itself.
This script fetches that implementation and runs it.

    ./regenerate-kat.py [--repo DIR] [--check]

With no argument it clones https://github.com/SHRINCS/shrincs-bip into a
temporary directory. The upstream commit is recorded in the output, so a
regenerated file that differs shows both that and the changed vectors.

With --check it writes nothing, and instead compares what upstream produces
against the committed file. Only the vectors count: upstream moving to a new
commit that produces the same vectors passes, with a note, since the crate is
then still tested against current values.
"""
import argparse, hashlib, json, os, subprocess, sys, tempfile

UPSTREAM = "https://github.com/SHRINCS/shrincs-bip"

def load(repo):
    sys.path.insert(0, os.path.join(repo, "impl"))
    import shrincs
    commit = subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
    return shrincs, commit

def grind_component(R, pk_seed, digest):
    """Grinds at the WOTS+C grinding address of height 0 and index 0.

    Upstream has passed that address two ways: as a raw 22-byte ADRS, and since
    SHRINCS/shrincs-bip#64 as a typed WotsCGrind record built from the height
    and index. Both serialize it to the same bytes, so the vectors do not depend
    on which one this checkout uses.
    """
    if hasattr(R, "WotsCGrind"):
        adrs = R.WotsCGrind(0, 0)
        counter, indexes = R.wots_c_grind_to_constant_sum(
            pk_seed, digest, node_height=0, node_index=0)
    else:
        adrs = bytearray(22)
        adrs[9] = R.SF_WOTS_C_GRIND
        counter, indexes = R.wots_c_grind_to_constant_sum(pk_seed, digest, adrs)
    return adrs, counter, indexes

def build(R, commit):
    h = lambda b: b.hex()
    seed = bytes(range(48))
    pk_seed = seed[32:48]

    digest = hashlib.sha256(b"component").digest()
    adrs, counter, indexes = grind_component(R, pk_seed, digest)
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
    ap.add_argument("--check", action="store_true",
                    help="compare with tests/kat.json instead of writing it")
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
    if args.check:
        return check(kat, out)
    with open(out, "w") as fh:
        json.dump(kat, fh, indent=1)
    print("wrote %s" % out)
    return 0

def check(kat, path):
    with open(path) as fh:
        committed = json.load(fh)
    vectors = lambda k: {key: v for key, v in k.items() if key != "_commit"}
    old, new = committed.get("_commit", "?")[:7], kat["_commit"][:7]
    if vectors(kat) != vectors(committed):
        print("tests/kat.json is stale: upstream %s produces different vectors "
              "from the committed %s; run ./regenerate-kat.py" % (new, old))
        return 1
    if old != new:
        print("vectors unchanged; upstream moved from %s to %s" % (old, new))
    else:
        print("vectors match upstream %s" % new)
    return 0

if __name__ == "__main__":
    sys.exit(main())
