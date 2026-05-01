#!/bin/bash

set -eu

SCENARIO="${1:-ir}"
SHAREDIR=/tmp/smite-nyx
AFLPP_PATH=/nix/store/isck0bnfyqdfmcyv94cp1g8nwsfmr89p-aflplusplus-4.35c

mkdir -p /tmp/smite-seeds

# The `ir` scenario needs the custom mutator; other scenarios take raw bytes.
if [ "$SCENARIO" = "ir" ]; then
    cargo build --release -p smite-ir-mutator
    printf '\x00' > /tmp/smite-seeds/empty
    AFL_ENV="AFL_NO_UI=1 AFL_CUSTOM_MUTATOR_LIBRARY=target/release/libsmite_ir_mutator.so AFL_CUSTOM_MUTATOR_ONLY=1 AFL_FRAMESHIFT_DISABLE=1"
else
    echo 'AAAA' > /tmp/smite-seeds/seed1
    AFL_ENV="AFL_NO_UI=1"
fi

env $AFL_ENV $AFLPP_PATH/bin/afl-fuzz -X \
    -i /tmp/smite-seeds -o /tmp/smite-out \
    -- $SHAREDIR 2>&1
