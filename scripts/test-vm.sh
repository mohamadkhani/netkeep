#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# LogiGuard Test VM — one-shot Ubuntu VM for firewall/eBPF development
# ---------------------------------------------------------------------------
# Usage:
#   ./scripts/test-vm.sh              # launch VM (downloads image on first run)
#   ./scripts/test-vm.sh --clean      # wipe overlay and start fresh
#   ./scripts/test-vm.sh --offline    # skip image download check
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/logiguard-vm"
mkdir -p "$CACHE_DIR"

# --- Config ----------------------------------------------------------------
UBUNTU_IMAGE="noble-server-cloudimg-amd64.img"
UBUNTU_URL="https://cloud-images.ubuntu.com/noble/current/${UBUNTU_IMAGE}"
BASE_IMAGE="$CACHE_DIR/$UBUNTU_IMAGE"
OVERLAY_IMAGE="$CACHE_DIR/logiguard-test.qcow2"
SEED_IMAGE="$CACHE_DIR/seed.img"

VM_MEMORY="${LOGIGUARD_VM_MEMORY:-4096}"
VM_CPUS="${LOGIGUARD_VM_CPUS:-4}"
VM_DISK="${LOGIGUARD_VM_DISK:-20G}"
SSH_PORT="${LOGIGUARD_VM_SSH_PORT:-2222}"
SPICE_PORT="${LOGIGUARD_VM_SPICE_PORT:-5900}"

# ---------------------------------------------------------------------------
# Parse flags
# ---------------------------------------------------------------------------
CLEAN=0 OFFLINE=0 HEADLESS=0
for arg in "$@"; do
    case "$arg" in
        --clean)   CLEAN=1 ;;
        --offline) OFFLINE=1 ;;
        --headless) HEADLESS=1 ;;
        -h|--help)
            echo "Usage: $0 [--clean] [--offline] [--headless]"
            echo ""
            echo "  --clean     Wipe overlay and start from fresh disk"
            echo "  --offline   Skip Ubuntu image download check"
            echo "  --headless  Run without GUI window (serial console, Ctrl-A X to quit)"
            echo ""
            echo "Env vars: LOGIGUARD_VM_MEMORY, LOGIGUARD_VM_CPUS, LOGIGUARD_VM_DISK, LOGIGUARD_VM_SSH_PORT"
            exit 0
            ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Step 1 — Download Ubuntu cloud image (once)
# ---------------------------------------------------------------------------
if [[ $OFFLINE -eq 0 ]] && [[ ! -f "$BASE_IMAGE" ]]; then
    echo "==> Downloading Ubuntu 24.04 cloud image (~600MB)..."
    curl -fSL --progress-bar -o "$BASE_IMAGE" "$UBUNTU_URL"
    echo "==> Done: $BASE_IMAGE"
fi

if [[ ! -f "$BASE_IMAGE" ]]; then
    echo "ERROR: Base image not found at $BASE_IMAGE"
    echo "       Run without --offline first to download it."
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2 — Create overlay image (throwaway disk)
# ---------------------------------------------------------------------------
if [[ $CLEAN -eq 1 ]] || [[ ! -f "$OVERLAY_IMAGE" ]]; then
    echo "==> Creating fresh overlay ($VM_DISK)..."
    qemu-img create -q -f qcow2 -F qcow2 -b "$BASE_IMAGE" "$OVERLAY_IMAGE" "$VM_DISK"
fi

# ---------------------------------------------------------------------------
# Step 3 — Generate cloud-init seed image (vfat, no extra tools needed)
# ---------------------------------------------------------------------------
echo "==> Generating cloud-init seed..."

# Detect host SSH public key
SSH_KEY=""
for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub" "$HOME/.ssh/id_ecdsa.pub"; do
    if [[ -f "$candidate" ]]; then
        SSH_KEY=$(cat "$candidate")
        break
    fi
done

if [[ -z "$SSH_KEY" ]]; then
    echo "WARNING: No SSH public key found. Password login will be enabled."
    SSH_KEY="ssh-rsa REPLACE_ME"
fi

cat > "$CACHE_DIR/meta-data" << 'METAEOF'
instance-id: logiguard-test
local-hostname: logiguard-vm
METAEOF

cat > "$CACHE_DIR/user-data" << USEREOF
#cloud-config
hostname: logiguard-vm
fqdn: logiguard-vm.local

users:
  - name: dev
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo, kvm
    shell: /bin/bash
    ssh_authorized_keys:
      - ${SSH_KEY}

package_update: true
package_upgrade: false

packages:
  # Rust / eBPF build toolchain
  - build-essential
  - clang
  - llvm
  - libclang-dev
  - libelf-dev
  - zlib1g-dev
  - pkg-config
  - curl
  # GPUI GUI dependencies
  - libx11-dev
  - libxkbcommon-dev
  - libxkbcommon-x11-dev
  - libwayland-dev
  - libgtk-3-dev
  - libfontconfig-dev
  # Firewall / network tools
  - nftables
  - bpftool
  - linux-tools-generic
  - tcpdump
  - netcat-openbsd
  # Dev tools
  - git
  - vim
  - tmux
  - htop
  - strace
  - linux-headers-generic

write_files:
  - path: /home/dev/.cargo/config.toml
    owner: dev:dev
    permissions: '0644'
    content: |
      [target.x86_64-unknown-linux-gnu]
      linker = "clang"
      rustflags = ["-C", "link-arg=-fuse-ld=lld"]

  - path: /etc/environment.d/logiguard.conf
    permissions: '0644'
    content: |
      LOGIGUARD_SOCKET_PATH=/run/logiguard/logiguard.sock

runcmd:
  # Install Rust nightly toolchain
  - sudo -u dev bash -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly'
  - sudo -u dev bash -c '/home/dev/.cargo/bin/rustup component add rust-src'
  - sudo -u dev bash -c '/home/dev/.cargo/bin/cargo +nightly install bpf-linker'

  # Enable nftables service
  - systemctl enable nftables

  # Mount BPF filesystem
  - mkdir -p /sys/fs/bpf
  - mount -t bpf bpf /sys/fs/bpf || true

  # Done marker
  - touch /var/lib/cloud/instance/provisioned

final_message: |
  ╔══════════════════════════════════════════════════════════════╗
  ║  LogiGuard Test VM — Ready                                   ║
  ║                                                              ║
  ║  SSH:   ssh dev@localhost -p ${SSH_PORT}                     ║
  ║  Repo:  /home/dev/logiguard (9p mount if --share used)       ║
  ║                                                              ║
  ║  Build inside VM:                                            ║
  ║    cd ~/logiguard                                            ║
  ║    cargo xtask build-ebpf-release                            ║
  ║    cargo build --workspace                                   ║
  ║                                                              ║
  ║  Run daemon (as root):                                       ║
  ║    sudo target/debug/logiguard-daemon                        ║
  ║                                                              ║
  ║  Run tests:                                                  ║
  ║    cargo test --workspace                                    ║
  ╚══════════════════════════════════════════════════════════════╝
USEREOF

# Create vfat seed image
dd if=/dev/zero of="$SEED_IMAGE" bs=1M count=2 status=none
mkfs.vfat -n cidata "$SEED_IMAGE" >/dev/null 2>&1

# Copy cloud-init files into seed image
MOUNT_POINT=$(mktemp -d)
trap 'sudo umount "$MOUNT_POINT" 2>/dev/null; rmdir "$MOUNT_POINT"' EXIT
sudo mount -o loop,uid="$(id -u)",gid="$(id -g)" "$SEED_IMAGE" "$MOUNT_POINT"
cp "$CACHE_DIR/meta-data" "$CACHE_DIR/user-data" "$MOUNT_POINT"/
sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"
trap - EXIT

echo "==> Seed image ready."

# ---------------------------------------------------------------------------
# Step 4 — Launch QEMU
# ---------------------------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  LogiGuard Test VM — Ubuntu 24.04                               ║"
echo "║                                                                ║"
echo "║  SSH:   ssh dev@localhost -p $SSH_PORT                         ║"
echo "║  Wait ~60s for cloud-init (first boot installs deps + Rust)    ║"
echo "║  Check: ssh dev@localhost -p $SSH_PORT 'cloud-init status'     ║"
echo "║                                                                ║"
echo "║  Dual NIC: enp0s2=mgmt(SSH)  enp0s3=test(192.168.100.0/24)    ║"
echo "║  Test firewall on enp0s3 without breaking your SSH session.    ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# Detect if we're in a graphical session
HAS_DISPLAY="${DISPLAY:-}"

QEMU_ARGS=(
    -enable-kvm
    -cpu host
    -m "$VM_MEMORY"
    -smp "$VM_CPUS"
    -machine type=q35,accel=kvm
    # --- Disks ---
    -drive file="$OVERLAY_IMAGE",if=virtio,format=qcow2,discard=unmap
    -drive file="$SEED_IMAGE",if=virtio,format=raw
    # --- Two NICs: mgmt (SSH) + test (firewall target) ---
    -netdev user,id=mgmt,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22
    -device virtio-net-pci,netdev=mgmt,mac=52:54:00:12:34:56
    -netdev user,id=test,net=192.168.100.0/24
    -device virtio-net-pci,netdev=test,mac=52:54:00:12:34:57
)

if [[ $HEADLESS -eq 1 ]] || [[ -z "$HAS_DISPLAY" ]]; then
    QEMU_ARGS+=(-nographic)
    echo "==> Headless mode — serial console (Ctrl-A X to quit)."
    echo "    SSH instead: ssh dev@localhost -p $SSH_PORT"
else
    QEMU_ARGS+=(-display gtk,gl=on -vga virtio)
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
