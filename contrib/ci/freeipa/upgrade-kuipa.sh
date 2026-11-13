#!/usr/bin/env bash
# Upgrade kuipa and kuipa-server on every VM of a running ci-freeipa nested
# environment to the RPMs in RPMDIR, and fail unless each VM ends up with
# exactly those builds.  The VMs are reached through the ssh_config that
# `freeipa-env up` wrote.
#
#   contrib/ci/freeipa/upgrade-kuipa.sh WORKDIR RPMDIR
set -euo pipefail

workdir="${1:?usage: $0 WORKDIR RPMDIR}"
rpms="$(realpath "${2:?usage: $0 WORKDIR RPMDIR}")"
cfg="$workdir/inner/ssh_config"
[[ -r $cfg ]] || { echo "no $cfg: has freeipa-env up run?" >&2; exit 1; }

want="$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$rpms"/*.rpm | sort)"

for host in $(awk '$1 == "Host" { print $2 }' "$cfg"); do
    echo "== $host: before"
    ssh -F "$cfg" "$host" 'rpm -q kuipa kuipa-server'
    ssh -F "$cfg" "$host" 'rm -rf /root/kuipa-rpms && mkdir /root/kuipa-rpms'
    scp -F "$cfg" "$rpms"/*.rpm "$host:/root/kuipa-rpms/"
    ssh -F "$cfg" "$host" 'dnf -y install /root/kuipa-rpms/*.rpm'
    have="$(ssh -F "$cfg" "$host" "rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' kuipa kuipa-server" | sort)"
    echo "== $host: after"
    echo "$have"
    [[ $have == "$want" ]] || { echo "$host: not at the built kuipa" >&2; exit 1; }
done
