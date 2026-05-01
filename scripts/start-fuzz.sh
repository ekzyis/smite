#!/bin/bash

set -eu

SHAREDIR=/tmp/smite-nyx
AFLPP_PATH=/nix/store/isck0bnfyqdfmcyv94cp1g8nwsfmr89p-aflplusplus-4.35c

mkdir -p /tmp/smite-seeds && echo 'AAAA' > /tmp/smite-seeds/seed1

# with or without mutators?
# AFL_ENV="AFL_CUSTOM_MUTATOR_LIBRARY=target/release/libsmite_ir_mutator.so AFL_CUSTOM_MUTATOR_ONLY=1 AFL_DISABLE_TRIM=1"
AFL_ENV="AFL_NO_UI=1"

env $AFL_ENV $AFLPP_PATH/bin/afl-fuzz -X \
    -i /tmp/smite-seeds -o /tmp/smite-out \
    -- $SHAREDIR 2>&1
