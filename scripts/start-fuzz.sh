#!/bin/bash

set -eu

TARGET=ldk
SCENARIO=ir
DEBUG=0
POS=0
for arg in "$@"; do
    case "$arg" in
        --debug) DEBUG=1 ;;
        *)
            POS=$((POS + 1))
            if [ "$POS" = 1 ]; then TARGET="$arg"; fi
            if [ "$POS" = 2 ]; then SCENARIO="$arg"; fi
            ;;
    esac
done

SHAREDIR=/tmp/smite-nyx
AFLPP_PATH=/nix/store/isck0bnfyqdfmcyv94cp1g8nwsfmr89p-aflplusplus-4.35c

mkdir -p /tmp/smite-seeds

# The `ir` scenario needs the custom mutator; other scenarios take raw bytes.
if [ "$SCENARIO" = "ir" ]; then
    cargo build --release -p smite-ir-mutator
    printf '\x00' > /tmp/smite-seeds/empty
    AFL_ENV="AFL_CUSTOM_MUTATOR_LIBRARY=target/release/libsmite_ir_mutator.so AFL_CUSTOM_MUTATOR_ONLY=1 AFL_FRAMESHIFT_DISABLE=1"
else
    echo 'AAAA' > /tmp/smite-seeds/seed1
    AFL_ENV=""
fi

# Show the AFL++ UI by default; --debug disables it so AFL and target logs are visible.
if [ "$DEBUG" = 1 ]; then
    AFL_ENV="AFL_NO_UI=1 $AFL_ENV"
fi

env $AFL_ENV $AFLPP_PATH/bin/afl-fuzz -X -T "$TARGET/$SCENARIO" \
    -i /tmp/smite-seeds -o /tmp/smite-out \
    -- $SHAREDIR 2>&1
