# Against the C++ implementation

[`BlockstreamResearch/shrincs-cpp`](https://github.com/BlockstreamResearch/shrincs-cpp)
is the other public SHRINCS implementation. This directory reproduces a
same-machine measurement of both.

## They are not the same scheme

This is the first thing to establish, because the timings are meaningless
without it. Read out of the C++ build at runtime, not from its README:

```
W=256 L=16 SWN=2040 HSF=210 HSL=32 D=4 B=17 K=11 N=16
WOTS_SIGN_LEN=292
```

against the draft this crate implements:

| | `shrincs-cpp` | draft BIP |
|---|---|---|
| Winternitz `w` | 256 | 16 |
| chains | 16 | 32 |
| target sum | 2040 | 240 |
| few-time component | PORS+FP | FORS |
| stateful tree | UXMSS only | FXMSS, any shape |

The C++ predates the draft: its README points at `shrincs-specification`, last
pushed April 2026, while the draft was announced from `SHRINCS/shrincs-bip` in
August. The draft explicitly declines PORS+FP — worth a further 15% at the same
budget — to stay black-box compatible with FIPS 205 and inherit its analysis.

## Reproducing

```sh
# the C++ side, in a container: upstream's Makefile resolves OpenSSL through
# Homebrew, which does not exist on Linux, so the image patches that one line
git clone https://github.com/BlockstreamResearch/shrincs-cpp
cp cpp.Dockerfile shrincs-cpp/Dockerfile
docker build -t shrincs-cpp shrincs-cpp/
docker run --rm shrincs-cpp make benchmark

# this crate, same four operations
cargo run --release --example bench
```

## Measured

One host, `SHRINCS_B32` for the C++ and UXMSS depth 255 at counter 0 here.

| | `shrincs-cpp` | this crate |
|---|---|---|
| stateful signature | 308 B | 548 B |
| stateful signing | 197.52 ms | 96.24 ms |
| stateful verification | 0.5017 ms | 0.1771 ms |
| stateless signature | 3,680 B | 5,777 B |
| stateless signing | 1932.92 ms | 1251.50 ms |
| stateless verification | 1.9423 ms | 1.0101 ms |

## The truncation demo

The repository carries `kat/truncation_bug_demo.cpp`, written to show that only
the first 32 bytes of a message reached the digest, so a signature verified
under any message sharing that prefix. Its header says as much: "Corruption
after byte 32 - expected Fail, but the result is Pass."

Built and run against the current HEAD, it no longer reproduces:

```
records:     20
result=Fail: 20
result=Pass:  0
```

The defect has been fixed and the demo survives as a regression artifact. It is
worth knowing about because it is the sharpest failure mode this family of
schemes has — a signature that covers a prefix rather than a message is a
universal forgery for anything sharing that prefix — and because nothing in the
draft's own test material probes for it. `the_whole_message_is_signed_not_a_prefix`
in `tests/kat.rs` runs the same probe against this crate, corrupting each of
eight positions in messages of six lengths, on both signing paths, and also
rejecting a message extended by one byte.

## What this does and does not show

The older design produces **smaller signatures and is slower**; the draft's
parameters are **larger and faster**. That is the direction the working group
described when they announced the draft — the stateful component was
reparameterised for performance at the cost of size — and these numbers are
consistent with it on both axes.

What the numbers cannot separate is parameter choice from implementation. The
two differ in language, author and optimisation effort as well as in scheme, so
none of the speed difference can be attributed to the parameters alone. Reading
this table as "Rust is twice as fast as C++" would be wrong; reading it as "the
two design points sit where their authors said they sit" is what it supports.
