#!/bin/bash
# dracut module: the tang-pqc Clevis pin in the initramfs, so
# clevis-luks-askpass can unlock volumes bound with `clevis luks bind ...
# tang-pqc` once the network is up (as the classic tang pin does).

check() {
    require_binaries tang-pqc clevis-decrypt-tang-pqc || return 1
    return 255
}

depends() {
    echo clevis network
    return 0
}

install() {
    inst_multiple tang-pqc clevis-decrypt-tang-pqc
    # The system crypto policy decides which ML-KEM and ML-DSA sets the
    # pin may use; without it OpenSSL's defaults apply.
    inst_multiple -o /etc/pki/tls/openssl.cnf \
        /etc/crypto-policies/back-ends/opensslcnf.config \
        /etc/crypto-policies/back-ends/openssl_fips.config
    # CA files named by bound volumes' "ca" settings must be added with
    # install_items+=" /path/to/ca.pem " in /etc/dracut.conf.d.
}
