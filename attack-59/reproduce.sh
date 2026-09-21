#!/bin/sh
# Regenerate the forgery and check both verifiers accept it.
# Usage: ./attack-59/reproduce.sh [REUSE_K] [DEPTH]   (run from the crate root)
set -e
K="${1:-4}"; D="${2:-6}"
python3 attack-59/forge.py --reuse-k "$K" --depth "$D"
echo "--- AppliedPQC/shrincs-rs verifier on the forged bytes (expect [{\"ok\":true}]):"
cargo run --release --quiet --example interop -- verify < attack-59/forged-job.json
echo "--- and on the 1-bit-tampered control (expect [{\"ok\":false}]):"
cargo run --release --quiet --example interop -- verify < attack-59/control-job.json
