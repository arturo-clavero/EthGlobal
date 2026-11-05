#!/usr/bin/env bash
# Prepare a dedicated, exactly pinned TLSN core (+ MPZ) checkout for native and WASM builds.
# Usage: prepare-core.sh /absolute/path/to/dedicated/core-checkout
#
# Prover and verifier must use the same patched core and the same backpressure implementation, so every build of
# the WASM prover prepares its checkout through this script.
#
# Provenance: the patches are not trusted because they sit next to this script. Each patch directory is pinned by a
# single sha256 in VERSION, taken over `sha256sum <sorted *.patch>`, so changing a patch's bytes, adding one or
# removing one all fail the check. Recompute with `prepare-core.sh --print-digests` after deliberately changing the
# series, and commit the new VERSION lines with the patches.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/VERSION"

# The digest of a patch directory: the set, the names and the bytes. An empty directory is never a valid series —
# it would otherwise silently prepare an unpatched core — so it is rejected here rather than digested.
patches_digest() {
    local found=0 f
    for f in "$1"/*.patch; do [ -e "$f" ] && found=1 && break; done
    [ "$found" = 1 ] || { echo "no *.patch files in $1; refusing to build" >&2; exit 1; }
    ( cd "$1" && LC_ALL=C ls -1 ./*.patch | LC_ALL=C sort | xargs -r sha256sum ) | sha256sum | cut -d' ' -f1
}

if [ "${1:-}" = '--print-digests' ]; then
    printf 'TLSN_CORE_PATCHES_SHA256=%s\n' "$(patches_digest "$HERE/patches")"
    printf 'TLSN_MPZ_PATCHES_SHA256=%s\n' "$(patches_digest "$HERE/mpz-patches")"
    exit 0
fi

DEST="${1:?usage: prepare-core.sh /absolute/path/to/dedicated/core-checkout}"
[ "$#" -eq 1 ] || { echo 'expected one dedicated checkout path' >&2; exit 1; }
case "$DEST" in /*) ;; *) echo 'core checkout must be an absolute path' >&2; exit 1 ;; esac
[ ! -L "$DEST" ] || { echo 'core checkout must not be a symlink' >&2; exit 1; }

# Check provenance before anything is cloned or applied.
for spec in "patches:$TLSN_CORE_PATCHES_SHA256" "mpz-patches:$TLSN_MPZ_PATCHES_SHA256"; do
    dir=${spec%%:*}; expected=${spec#*:}
    [ -d "$HERE/$dir" ] || { echo "missing patch directory $HERE/$dir" >&2; exit 1; }
    actual=$(patches_digest "$HERE/$dir")
    [ "$actual" = "$expected" ] || {
        echo "$dir does not match its pinned digest ($actual != $expected); refusing to build" >&2; exit 1;
    }
done

mkdir -p -- "$(dirname -- "$DEST")"
# Serialize preparation; builds subsequently read the immutable patched tree.
exec 9>"$DEST.prepare.lock"
flock -x 9

# patches/0002 points mpz-zk at the path "mpz/crates/zk", so the MPZ checkout must sit inside the core tree.
# Git reports that nested repository as an untracked `mpz/`, so the core's own cleanliness checks exclude it; MPZ
# is checked as a repository in its own right.
NESTED=mpz

# Files the patches in a series directory create: the only untracked files allowed in a prepared checkout.
created_by() {
    local patch
    for patch in "$1"/*.patch; do git apply --summary "$patch"; done | sed -n 's/^ create mode [0-7]* //p'
}

# Untracked files in a repo, other than those its patch series creates, ignoring the nested MPZ checkout when
# looking at the core.
untracked() {
    local listed
    if [ "$2" = with-nested ]; then
        listed=$(git -C "$1" ls-files --others --exclude-standard -- . ":(exclude)$NESTED")
    else
        listed=$(git -C "$1" ls-files --others --exclude-standard)
    fi
    [ -n "$listed" ] || return 0
    printf '%s\n' "$listed" | grep -vxF -f <(created_by "$3") || true
}

# A pinned commit, fetched by object id: a moved tag cannot change what is built.
fetch_pinned() {
    repo="$1" url="$2" commit="$3" series="$4" nested="${5:-no-nested}"
    if [ ! -e "$repo" ]; then
        git init --quiet "$repo"
        git -C "$repo" remote add origin "$url"
        git -C "$repo" fetch --quiet --depth 1 origin "$commit"
        git -C "$repo" checkout --quiet --detach FETCH_HEAD
    fi
    [ "$(git -C "$repo" rev-parse HEAD)" = "$commit" ] || {
        echo "unexpected commit in $repo (want $commit); refusing to modify checkout" >&2; exit 1;
    }
    [ -z "$(untracked "$repo" "$nested" "$series")" ] || {
        echo "untracked files in $repo; refusing to modify checkout" >&2; exit 1;
    }
    git -C "$repo" diff --cached --quiet || {
        echo "staged changes in $repo; refusing to modify checkout" >&2; exit 1;
    }
}

# Apply a series idempotently: a patch already present reverse-applies, so it is skipped rather than reapplied.
apply_series() {
    repo="$1" dir="$2" nested="${3:-no-nested}"
    for patch in "$dir"/*.patch; do
        if git -C "$repo" apply --reverse --check "$patch" 2>/dev/null; then
            continue
        fi
        git -C "$repo" apply --check "$patch"
        git -C "$repo" apply "$patch"
    done
    # Every patch must now be present, and nothing may have appeared beside them: together with the digest check
    # above this guarantees no unrelated mutation of the checkout.
    for patch in "$dir"/*.patch; do
        git -C "$repo" apply --reverse --check "$patch" || {
            echo "$(basename "$patch") is not cleanly present in $repo; refusing to build" >&2; exit 1;
        }
    done
    [ -z "$(untracked "$repo" "$nested" "$dir")" ] || {
        echo "untracked files in $repo after patching; refusing to build" >&2; exit 1;
    }
}

fetch_pinned "$DEST" https://github.com/tlsnotary/tlsn.git "$TLSN_CORE_COMMIT" "$HERE/patches" with-nested
MPZ="$DEST/$NESTED"
fetch_pinned "$MPZ" https://github.com/privacy-ethereum/mpz.git "$TLSN_MPZ_COMMIT" "$HERE/mpz-patches"

apply_series "$MPZ" "$HERE/mpz-patches"
apply_series "$DEST" "$HERE/patches" with-nested

printf '%s\n' "$DEST"
