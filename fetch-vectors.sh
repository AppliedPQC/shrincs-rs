#!/bin/sh
# Download NIST's ACVP vectors for SLH-DSA, used by tests/acvp.rs.
#
# keyGen and sigGen carry inputs and expected outputs; sigVer carries curated
# invalid signatures and the reason each must be rejected. Together they
# check this crate against NIST rather than against itself. Roughly 67 MB, and
# not kept in the repository. Without them tests/acvp.rs skips.
set -e
cd "$(dirname "$0")"
mkdir -p vectors
cd vectors
ACVP="https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files"
for d in SLH-DSA-keyGen-FIPS205 SLH-DSA-sigGen-FIPS205 SLH-DSA-sigVer-FIPS205; do
    if [ -s "$d.json" ]; then
        echo "have    $d.json"
    else
        echo "fetch   $d.json"
        curl -sfLo "$d.json" "$ACVP/$d/internalProjection.json"
    fi
done
