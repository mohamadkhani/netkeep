#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# build-and-release.sh — Build the Arch package and upload it to Gitea via tea
#
# Usage:
#   ./packaging/archlinux/build-and-release.sh [OPTIONS]
#
# Options:
#   --tag <tag>          Tag / version for the release (default: from PKGBUILD pkgver)
#   --title <title>      Release title (default: "LogiGuard <tag>")
#   --notes <text>       Release notes (default: "Release <tag>")
#   --notes-file <path>  Read release notes from a file (overrides --notes)
#   --prerelease         Mark as pre-release
#   --draft              Mark as draft
#   --skip-build         Skip makepkg, just upload existing .pkg.tar.zst
#   --skip-upload        Build only, don't upload to Gitea
#   --login <name>       tea login name (uses default if omitted)
#   --repo <slug>        Gitea repo slug (default: auto-detected from git remote)
#   --help               Show this help
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────
TAG=""
TITLE=""
NOTES=""
NOTES_FILE=""
PRERELEASE=false
DRAFT=false
SKIP_BUILD=false
SKIP_UPLOAD=false
TEA_LOGIN=""
TEA_REPO=""

# ── Parse arguments ───────────────────────────────────────────────────────
show_help() {
    sed -n '3,/^# -\+/p' "$0" | sed 's/^# \?//'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tag)         TAG="$2";         shift 2 ;;
        --title)       TITLE="$2";       shift 2 ;;
        --notes)       NOTES="$2";       shift 2 ;;
        --notes-file)  NOTES_FILE="$2";  shift 2 ;;
        --prerelease)  PRERELEASE=true;  shift   ;;
        --draft)       DRAFT=true;       shift   ;;
        --skip-build)  SKIP_BUILD=true;  shift   ;;
        --skip-upload) SKIP_UPLOAD=true; shift   ;;
        --login)       TEA_LOGIN="$2";   shift 2 ;;
        --repo)        TEA_REPO="$2";    shift 2 ;;
        --help|-h)     show_help ;;
        *)
            echo "error: unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# ── Read pkgver from PKGBUILD ─────────────────────────────────────────────
source "${SCRIPT_DIR}/PKGBUILD"  # provides: pkgver pkgrel pkgname

if [[ -z "$TAG" ]]; then
    TAG="v${pkgver}"
fi

if [[ -z "$TITLE" ]]; then
    TITLE="LogiGuard ${TAG}"
fi

echo "==> Package : ${pkgname}"
echo "==> Version : ${pkgver}-${pkgrel}"
echo "==> Tag     : ${TAG}"
echo "==> Title   : ${TITLE}"

# ── Build ─────────────────────────────────────────────────────────────────
if [[ "$SKIP_BUILD" == false ]]; then
    echo ""
    echo ":: Building package with makepkg..."
    (cd "${SCRIPT_DIR}" && makepkg -sf)

    echo ""
    echo ":: Build complete."
fi

# ── Locate the built package ──────────────────────────────────────────────
# The glob pattern accounts for any arch suffix (x86_64 or any)
PKG_FILE="$(find "${SCRIPT_DIR}" -maxdepth 1 -name "${pkgname}-${pkgver}-${pkgrel}-*.pkg.tar.zst" | head -n 1)"

if [[ -z "$PKG_FILE" ]]; then
    echo "error: no built package found matching ${pkgname}-${pkgver}-${pkgrel}-*.pkg.tar.zst in ${SCRIPT_DIR}" >&2
    exit 1
fi

echo "==> Package file: ${PKG_FILE} ($(du -h "$PKG_FILE" | cut -f1))"

if [[ "$SKIP_UPLOAD" == true ]]; then
    echo ""
    echo ":: --skip-upload given; not uploading."
    echo "   Package is at: ${PKG_FILE}"
    exit 0
fi

# ── Verify tea is available ───────────────────────────────────────────────
if ! command -v tea &>/dev/null; then
    echo "error: 'tea' CLI not found. Install it: https://gitea.com/gitea/tea" >&2
    exit 1
fi

# ── Verify tea login exists ───────────────────────────────────────────────
TEA_ARGS=()
[[ -n "$TEA_LOGIN" ]] && TEA_ARGS+=(--login "$TEA_LOGIN")
[[ -n "$TEA_REPO" ]]  && TEA_ARGS+=(--repo "$TEA_REPO")

# Try to detect repo from git remote if --repo wasn't given
if [[ -z "$TEA_REPO" ]]; then
    REMOTE_URL="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
    # Convert git@git.logicamp.dev:logicamp/logiguard.git → logicamp/logiguard
    if [[ "$REMOTE_URL" =~ ^git@[^:]+:(.+)\.git$ ]]; then
        TEA_REPO="${BASH_REMATCH[1]}"
        echo "==> Auto-detected repo: ${TEA_REPO}"
    elif [[ "$REMOTE_URL" =~ ^https?://[^/]+/(.+)\.git$ ]]; then
        TEA_REPO="${BASH_REMATCH[1]}"
        echo "==> Auto-detected repo: ${TEA_REPO}"
    elif [[ "$REMOTE_URL" =~ ^https?://[^/]+/(.+)$ ]]; then
        TEA_REPO="${BASH_REMATCH[1]}"
        echo "==> Auto-detected repo: ${TEA_REPO}"
    fi
    [[ -n "$TEA_REPO" ]] && TEA_ARGS+=(--repo "$TEA_REPO")
fi

echo ""
echo ":: Checking tea login..."
if ! tea "${TEA_ARGS[@]}" whoami &>/dev/null; then
    echo "error: tea is not logged in. Run:" >&2
    echo "  tea login add --name logicamp --url https://git.logicamp.dev --token <YOUR_TOKEN>" >&2
    exit 1
fi

TEA_USER="$(tea "${TEA_ARGS[@]}" whoami 2>/dev/null | head -1 || echo "unknown")"
echo "   Logged in as: ${TEA_USER}"

# ── Create or update the release ──────────────────────────────────────────
echo ""
echo ":: Creating release ${TAG}..."

RELEASE_CMD=(tea releases create)
RELEASE_CMD+=(--tag "$TAG")
RELEASE_CMD+=(--title "$TITLE")

if [[ -n "$NOTES_FILE" ]]; then
    RELEASE_CMD+=(--note-file "$NOTES_FILE")
elif [[ -n "$NOTES" ]]; then
    RELEASE_CMD+=(--note "$NOTES")
else
    RELEASE_CMD+=(--note "Release ${TAG}")
fi

[[ "$PRERELEASE" == true ]] && RELEASE_CMD+=(--prerelease)
[[ "$DRAFT" == true ]]      && RELEASE_CMD+=(--draft)

RELEASE_CMD+=(--asset "$PKG_FILE")
RELEASE_CMD+=("${TEA_ARGS[@]}")

echo "   Running: ${RELEASE_CMD[*]}"
"${RELEASE_CMD[@]}"

echo ""
echo "==> Done! Release ${TAG} published with asset:"
echo "    $(basename "$PKG_FILE")"
