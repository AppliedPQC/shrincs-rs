#!/usr/bin/env python3
"""Cross-verify this crate against the draft's reference implementation.

Byte-equality of signatures, which tests/kat.json checks, tests only the
signer: if both sides produce the same bytes, nothing has been learned about
either verifier. This drives both directions instead.

    Rust signs   -> Python verifies      does upstream accept what we produce?
    Python signs -> Rust verifies        do we accept what upstream produces?
    both mutate  -> both must reject     do we reject exactly what upstream does?

It also pins the behaviour of the caller-supplied randomness. The draft says
opt_rand is "unused in the stateful path", so on the stateless path a different
value must give a different signature, and on the stateful path it must give
the same one. Both are checked against upstream rather than assumed.

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

    # ---- caller-supplied randomness, agreed byte for byte ---------------
    rand_jobs, rand_meta = [], []
    for job in jobs:
        r = bytes(rng.randrange(256) for _ in range(16))
        rand_jobs.append(dict(job, opt_rand=r.hex()))
        rand_meta.append(r)
    rand_out = rust("sign", rand_jobs)
    rand_bad = 0
    for job, r, got in zip(jobs, rand_meta, rand_out):
        sf = bytes([job["shape"], job["depth"]])
        sk, _ = R.shrincs_keygen(bytes.fromhex(job["seed"]), sf)
        want = R.shrincs_sign(bytes.fromhex(job["msg"]), bytes.fromhex(job["ctx"]),
                              sk, job["ctr"], r)
        if bytes.fromhex(got["sig"]) != want:
            print(f"  randomised signature differs: {job['shape']}/{job['depth']} ctr={job['ctr']}")
            rand_bad += 1
    print(f"  explicit opt_rand, byte-identical: {len(jobs) - rand_bad}/{len(jobs)}")

    # ---- and it is used on one path and ignored on the other ------------
    stateless_varies = stateful_ignores = 0
    n_sl = n_sf = 0
    for job in jobs:
        a = dict(job, opt_rand=("11" * 16))
        b = dict(job, opt_rand=("22" * 16))
        sig_a, sig_b = rust("sign", [a, b])
        differs = sig_a["sig"] != sig_b["sig"]
        if job["ctr"] is None:
            n_sl += 1
            stateless_varies += differs
            if not differs:
                print("  stateless signature did not change with opt_rand")
        else:
            n_sf += 1
            stateful_ignores += not differs
            if differs:
                print("  stateful signature changed with opt_rand, which is unused there")
    print(f"  opt_rand changes the stateless signature : {stateless_varies}/{n_sl}")
    print(f"  opt_rand ignored by the stateful path    : {stateful_ignores}/{n_sf}")

    ok = (bad == 0 and agree == len(expect) and rand_bad == 0
          and stateless_varies == n_sl and stateful_ignores == n_sf)
    print("cross-verification:", "OK" if ok else "MISMATCH")
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
