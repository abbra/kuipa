#!/usr/bin/env bash
# Build the kuipa and kuipa-server RPMs of this checkout for the FreeIPA
# integration job (.github/workflows/freeipa.yml).  Runs as root in a Fedora
# container with the COPR repositories abbra/pqc and abbra/rust-deps enabled
# (they carry the crates and libraries Fedora lacks).
#
#   contrib/ci/freeipa/build-rpms.sh OUTDIR
set -euo pipefail

out="$(realpath -m "${1:?usage: $0 OUTDIR}")"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
pkgs="$root/contrib/packages"
top="$(mktemp -d)"
# The checkout belongs to another user in a GitHub container job: git archive
# (make tarball) refuses it otherwise.
git config --global --add safe.directory "$root"
trap 'rm -rf "$top"' EXIT

dnf install -y rpm-build rpmdevtools dnf-plugins-core git-core make python3 \
    cargo cargo-rpm-macros cargo-vendor-filterer

# The build time, not the commit time, goes into Release: the result must
# upgrade the kuipa that abbra/pqc installs next to FreeIPA, whatever commit
# that was built from.
snapdate="$(date -u +%Y%m%d%H%M)"
make -C "$pkgs" sources srpm SNAPDATE="$snapdate"
srpm="$(ls -t "$pkgs"/kuipa-*.src.rpm | head -n1)"

# --without clevis: the tang-pqc Clevis pin is not what a FreeIPA realm tests.
# --without check: the unit tests have their own jobs (ci.yml).
rb=(rpmbuild --rebuild --without check --without clevis
    --define "_topdir $top" "$srpm")
dnf builddep -y "$srpm"
# %generate_buildrequires adds crate() BuildRequires only once the sources are
# unpacked: rpmbuild stops with 11 and a buildreqs source package for dnf.
rc=0; "${rb[@]}" || rc=$?
if [[ $rc -eq 11 ]]; then
    dnf builddep -y "$top"/SRPMS/*.buildreqs.nosrc.rpm
    "${rb[@]}"
elif [[ $rc -ne 0 ]]; then
    exit "$rc"
fi

mkdir -p "$out"
cp "$top"/RPMS/*/kuipa-0*.rpm "$top"/RPMS/*/kuipa-server-0*.rpm "$out"/
ls -l "$out"
