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
