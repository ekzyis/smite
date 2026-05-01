#!/bin/bash

set -eu

SHAREDIR=/tmp/smite-nyx
AFLPP_PATH=$(readlink $(which afl-fuzz) | cut -d/ -f1-4)

mkdir -p /tmp/smite-seeds && echo 'AAAA' > /tmp/smite-seeds/seed1

cargo build --release -p smite-ir-mutator

# with or without mutators?
# AFL_ENV="AFL_CUSTOM_MUTATOR_LIBRARY=target/release/libsmite_ir_mutator.so"
# AFL_ENV="$AFL_ENV AFL_CUSTOM_MUTATOR_ONLY=1"
# AFL_ENV="$AFL_ENV AFL_DISABLE_TRIM=1"
# AFL_ENV="$AFL_ENV AFL_FRAMESHIFT_DISABLE=1"
# AFL_ENV="$AFL_ENV AFL_NO_UI=1"
AFL_ENV="AFL_NO_UI=1"

env $AFL_ENV $AFLPP_PATH/bin/afl-fuzz -X \
    -i /tmp/smite-seeds -o /tmp/smite-out \
    -- $SHAREDIR 2>&1
