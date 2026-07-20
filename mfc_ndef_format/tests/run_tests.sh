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
    "$app_dir/ndef_layout.c" \
    "$script_dir/test_ndef_layout.c" \
    -o "$script_dir/test_ndef_layout"

"$script_dir/test_ndef_layout"
