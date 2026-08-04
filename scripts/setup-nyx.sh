#!/bin/bash
#
# Modified setup script for Nyx mode fuzzing with AFL++
#
# Usage: ./scripts/setup-nyx.sh <target> <scenario>
#
# Environment Variables:
#   NYX_MEM_MB: Sets the memory allocation for the Nyx VM in MB (default: 2048).
#
# Example:
#   NYX_MEM_MB=4096 ./scripts/setup-nyx.sh lnd encrypted_bytes
#

set -e

TARGET=""
SCENARIO=""
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

if [ -z "$TARGET" ] || [ -z "$SCENARIO" ]; then
    echo "Usage: $0 <target> <scenario> [--debug]"
    exit 1
fi

DOCKER_IMAGE="smite-$TARGET-$SCENARIO"
SHAREDIR=/tmp/smite-nyx
AFLPP_PATH=/nix/store/isck0bnfyqdfmcyv94cp1g8nwsfmr89p-aflplusplus-4.35c

# Single EXIT handler: revert the debug patch (if applied) and remove the temp
# dir created later for Nyx config generation. bash keeps only one EXIT trap, so
# both must go through here.
DEBUG_PATCH=scripts/target_debug.patch
FORCE_FORK_DIR="$(mktemp -d)"
cleanup() {
    if [ "$DEBUG" = 1 ]; then
        # don't patch the file we're currently running
        # it's included in the patch for manual apply
        git apply -R --exclude=scripts/setup-nyx.sh "$DEBUG_PATCH" 2>/dev/null || true
    fi
    if [ -n "$FORCE_FORK_DIR" ]; then
        rm -rf "$FORCE_FORK_DIR"
    fi
}
trap cleanup EXIT

# In debug mode, patch the target so it surfaces its logs (init.sh tees to
# stdout, LND child stdio inherited), then build the image with it. The patch's
# setup-nyx.sh hunk is excluded to avoid rewriting this running script; its
# live-hcat effect is reproduced by a sed on the generated fuzz_no_pt.sh below.
if [ "$DEBUG" = 1 ]; then
    git apply --exclude=scripts/setup-nyx.sh "$DEBUG_PATCH"
    echo "~~~ debug mode: patch applied: $DEBUG_PATCH ~~~"
    git diff
fi

docker build -t "$DOCKER_IMAGE" -f workloads/$TARGET/Dockerfile --build-arg SCENARIO=$SCENARIO .

# Validate AFL++ path
if [ ! -d "$AFLPP_PATH/nyx_mode/packer/packer" ]; then
    echo "Error: AFL++ not found at $AFLPP_PATH"
    echo "Make sure AFL++ is installed with Nyx mode support."
    echo "See: https://github.com/AFLplusplus/AFLplusplus/blob/stable/nyx_mode/README.md"
    exit 1
fi

# Validate Docker image exists
if ! docker image inspect "$DOCKER_IMAGE" > /dev/null 2>&1; then
    echo "Error: Docker image '$DOCKER_IMAGE' not found."
    echo "Build it first with: docker build -t $DOCKER_IMAGE -f workloads/<target>/Dockerfile ."
    exit 1
fi

PACKER_PATH="$AFLPP_PATH/nyx_mode/packer/packer"
BINARIES_PATH="$PACKER_PATH/linux_x86_64-userspace/bin64"

# Check if packer binaries exist, compile if needed
if [ ! -f "$BINARIES_PATH/hget" ]; then
    echo "Compiling packer binaries..."
    (cd "$PACKER_PATH/linux_x86_64-userspace" && bash compile_64.sh)
fi

echo "Creating sharedir at: $SHAREDIR"
rm -rf "$SHAREDIR"
mkdir -p "$SHAREDIR"

# Export Docker container filesystem
echo "Exporting Docker container to container.tar..."
CONTAINER_ID=$(docker create "$DOCKER_IMAGE")
docker export "$CONTAINER_ID" -o "$SHAREDIR/container.tar"
docker rm "$CONTAINER_ID" > /dev/null

# Copy packer binaries
echo "Copying packer binaries..."
cp "$BINARIES_PATH"/* "$SHAREDIR/"

# Generate Nyx config.
#
# Python 3.14 changed the default multiprocessing start method to 'forkserver',
# which breaks the packer's common/debug.py. We force 'fork' via a
# sitecustomize.py injected on PYTHONPATH to restore the pre-3.14 behavior.
echo "Generating Nyx config..."
cat > "$FORCE_FORK_DIR/sitecustomize.py" <<'EOF'
import multiprocessing
multiprocessing.set_start_method("fork", force=True)
EOF

# The memory allocated to a single QEMU VM instance. Defaults to 2048 MB.
NYX_MEM_MB="${NYX_MEM_MB:-2048}"
echo "Using VM image size: ${NYX_MEM_MB} MB"

(cd "$PACKER_PATH" && PYTHONPATH="$FORCE_FORK_DIR${PYTHONPATH:+:$PYTHONPATH}" ./nyx_config_gen.py "$SHAREDIR" Kernel -m "$NYX_MEM_MB")

# Create fuzz_no_pt.sh script
echo "Creating fuzz_no_pt.sh..."
cat > "$SHAREDIR/fuzz_no_pt.sh" << 'EOF'
chmod +x hget
cp hget /tmp
cd /tmp
echo 0 > /proc/sys/kernel/randomize_va_space
echo 0 > /proc/sys/kernel/printk
./hget hcat_no_pt hcat
./hget habort_no_pt habort
chmod +x ./hcat
chmod +x ./habort
./hget container.tar container.tar
export __AFL_DEFER_FORKSRV=1
ip addr add 127.0.0.1/8 dev lo
ip addr add ::1/128 dev lo
ip link set lo up
ip a | ./hcat
mkdir rootfs/ && tar -xf container.tar -C /tmp/rootfs
mount -t proc /proc rootfs/proc/
mount --rbind /sys rootfs/sys/
mount --rbind /dev rootfs/dev/
echo '127.0.0.1 localhost' > rootfs/etc/hosts
echo '::1 localhost' >> rootfs/etc/hosts
echo '# No nameserver configured' > rootfs/etc/resolv.conf
chroot /tmp/rootfs /init.sh
cat rootfs/init.log | ./hcat
./habort "$(tail rootfs/init.log)"
EOF
chmod +x "$SHAREDIR/fuzz_no_pt.sh"

# In debug mode, stream the target's chroot stdout live via hcat. This is the
# excluded setup-nyx.sh hunk of target_debug.patch, applied to the generated
# file instead of this running script.
if [ "$DEBUG" = 1 ]; then
    sed -i 's#^chroot /tmp/rootfs /init.sh$#chroot /tmp/rootfs /init.sh | ./hcat#' "$SHAREDIR/fuzz_no_pt.sh"
    echo "~~~               debug mode               ~~~"
    echo "~~~ replaced                               ~~~"
    echo "~~~   chroot /tmp/rootfs /init.sh          ~~~"
    echo "~~~ with                                   ~~~"
    echo "~~~   chroot /tmp/rootfs /init.sh | ./hcat ~~~"
fi

echo ""
echo "Sharedir created successfully at: $SHAREDIR"
echo ""
echo "Contents:"
ls -lh "$SHAREDIR"
echo ""
echo "To start fuzzing, run:"
echo "  mkdir -p /tmp/smite-seeds && echo 'AAAA' > /tmp/smite-seeds/seed1"
echo "  $AFLPP_PATH/bin/afl-fuzz -X -i /tmp/smite-seeds -o /tmp/smite-out -- $SHAREDIR"
