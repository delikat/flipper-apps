#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
app_dir=$(dirname -- "$script_dir")

cc \
    -std=c11 \
    -Wall \
    -Wextra \
    -Werror \
    -pedantic \
    -I"$app_dir" \
    "$app_dir/tesla_apdu.c" \
    "$script_dir/test_apdu.c" \
    -o "$script_dir/test_apdu"

"$script_dir/test_apdu"
python3 "$script_dir/test_crypto_vector.py"

# Links the actual vendored mbedTLS (lib/mbedtls) and asserts the P-256 ECDH
# still yields the pinned shared secret, guarding the fast-crypto config change.
# mbedTLS sources aren't -Werror/-pedantic clean, so build them relaxed; only the
# ECDH closure is needed (ecdsa.c pulls in asn1_* the firmware provides on device).
cc \
    -std=c11 \
    -O2 \
    -Wno-redundant-decls \
    -I"$app_dir/lib/mbedtls/include" \
    -I"$app_dir/lib/mbedtls/library" \
    "$app_dir/lib/mbedtls/library/bignum.c" \
    "$app_dir/lib/mbedtls/library/bignum_core.c" \
    "$app_dir/lib/mbedtls/library/ecp.c" \
    "$app_dir/lib/mbedtls/library/ecp_curves.c" \
    "$app_dir/lib/mbedtls/library/platform_util.c" \
    "$script_dir/test_ecdh_vector.c" \
    -o "$script_dir/test_ecdh_vector"

"$script_dir/test_ecdh_vector"
