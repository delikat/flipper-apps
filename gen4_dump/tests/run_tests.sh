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
    "$app_dir/gen4_dump_core.c" \
    "$script_dir/test_gen4_dump_core.c" \
    -o "$script_dir/test_gen4_dump_core"

"$script_dir/test_gen4_dump_core"
