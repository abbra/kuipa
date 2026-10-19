#!/bin/sh
# Install the tang-pqc client and its Clevis pin:
#   contrib/clevis/install.sh [PREFIX] [DESTDIR]
# PREFIX defaults to /usr; the binary comes from target/release, or
# TANG_PQC_BIN.
set -eu
prefix=${1:-/usr}
destdir=${2:-}
here=$(cd "$(dirname "$0")" && pwd)
bin="$destdir$prefix/bin"
install -D -m 0755 "${TANG_PQC_BIN:-$here/../../target/release/tang-pqc}" "$bin/tang-pqc"
# The pin is the same binary, chosen by its name.
ln -sf tang-pqc "$bin/clevis-encrypt-tang-pqc"
ln -sf tang-pqc "$bin/clevis-decrypt-tang-pqc"
# Unlocking at boot: the dracut module brings the pin into the initramfs.
dracut="$destdir$prefix/lib/dracut/modules.d/60clevis-pin-tang-pqc"
install -D -m 0755 "$here/dracut/60clevis-pin-tang-pqc/module-setup.sh" "$dracut/module-setup.sh"
