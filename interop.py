#!/usr/bin/env python3
"""Cross-verify this crate against the draft's reference implementation.

Byte-equality of signatures, which tests/kat.json checks, tests only the
signer: if both sides produce the same bytes, nothing has been learned about
either verifier. This drives both directions instead.

    Rust signs   -> Python verifies      does upstream accept what we produce?
    Python signs -> Rust verifies        do we accept what upstream produces?
    both mutate  -> both must reject     do we reject exactly what upstream does?

    ./interop.py [--repo DIR] [--cases N]

With no --repo it clones the draft repository into a temporary directory.
"""
import argparse, json, os, random, subprocess, sys, tempfile

UPSTREAM = "https://github.com/SHRINCS/shrincs-bip"
HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = ["cargo", "run", "-q", "--release", "--example", "interop", "--"]

def rust(mode, jobs):
    p = subprocess.run(ORACLE + [mode], cwd=HERE, input=json.dumps(jobs),
                       capture_output=True, text=True)
    if p.returncode:
        sys.exit("rust oracle failed:\n" + p.stderr[-2000:])
    return json.loads(p.stdout)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo")
    ap.add_argument("--cases", type=int, default=12)
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        repo = args.repo
        if not repo:
            repo = os.path.join(tmp, "shrincs-bip")
            subprocess.check_call(["git", "clone", "-q", UPSTREAM, repo])
        sys.path.insert(0, os.path.join(repo, "impl"))
        import shrincs as R
        commit = subprocess.check_output(["git", "-C", repo, "rev-parse", "--short", "HEAD"],
                                         text=True).strip()
    print(f"upstream {commit}, {args.cases} random cases")

    rng = random.Random(20260828)
    jobs = []
    for _ in range(args.cases):
        shape = rng.choice([0, 1])
        depth = rng.randrange(1, 6) if shape else rng.randrange(1, 9)
        budget = depth + 1 if shape == 0 else 2 ** depth
        stateless = rng.random() < 0.25
        jobs.append({
            "seed": bytes(rng.randrange(256) for _ in range(48)).hex(),
            "shape": shape, "depth": depth,
            "ctr": None if stateless else rng.randrange(budget),
            "msg": bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300))).hex(),
            "ctx": bytes(rng.randrange(256) for _ in range(rng.randrange(0, 8))).hex(),
        })

    # ---- Rust signs, Python verifies ------------------------------------
    signed = rust("sign", jobs)
    bad = 0
    for job, got in zip(jobs, signed):
        sig, pk = bytes.fromhex(got["sig"]), bytes.fromhex(got["pubkey"])
        msg, ctx = bytes.fromhex(job["msg"]), bytes.fromhex(job["ctx"])
        sf = bytes([job["shape"], job["depth"]])
        _, pk_ref = R.shrincs_keygen(bytes.fromhex(job["seed"]), sf)
        if pk != pk_ref:
            print("  public key mismatch"); bad += 1; continue
        if not R.shrincs_verify(msg, sig, ctx, pk_ref):
            print(f"  upstream REJECTED our signature: {job['shape']}/{job['depth']} ctr={job['ctr']}")
            bad += 1
    print(f"  rust signs   -> python verifies : {len(jobs) - bad}/{len(jobs)}")

    # ---- Python signs, Rust verifies ------------------------------------
    checks, expect = [], []
    for job in jobs:
        sf = bytes([job["shape"], job["depth"]])
        sk, pk = R.shrincs_keygen(bytes.fromhex(job["seed"]), sf)
        msg, ctx = bytes.fromhex(job["msg"]), bytes.fromhex(job["ctx"])
        sig = R.shrincs_sign(msg, ctx, sk, job["ctr"], None)
        checks.append({"pubkey": pk.hex(), "msg": msg.hex(), "ctx": ctx.hex(), "sig": sig.hex()})
        expect.append(True)
        # and the same signature under a corrupted message, and a corrupted
        # signature: upstream rejects both, and so must we
        if msg:
            i = rng.randrange(len(msg))
            m2 = bytearray(msg); m2[i] ^= 1
            checks.append({"pubkey": pk.hex(), "msg": bytes(m2).hex(), "ctx": ctx.hex(), "sig": sig.hex()})
            expect.append(R.shrincs_verify(bytes(m2), sig, ctx, pk))
        j = rng.randrange(len(sig))
        s2 = bytearray(sig); s2[j] ^= 1
        checks.append({"pubkey": pk.hex(), "msg": msg.hex(), "ctx": ctx.hex(), "sig": bytes(s2).hex()})
        expect.append(R.shrincs_verify(msg, bytes(s2), ctx, pk))

    got = [r["ok"] for r in rust("verify", checks)]
    agree = sum(1 for a, b in zip(got, expect) if a == b)
    for k, (a, b) in enumerate(zip(got, expect)):
        if a != b:
            print(f"  disagreement on check {k}: rust={a} upstream={b}")
    print(f"  python signs -> rust verifies   : {agree}/{len(expect)} agree "
          f"({sum(expect)} accept, {len(expect) - sum(expect)} reject)")

    ok = bad == 0 and agree == len(expect)
    print("cross-verification:", "OK" if ok else "MISMATCH")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
