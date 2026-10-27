//! `kuipa escrow luks` and `kuipa escrow file` (`DESIGN-recovery.md` §5):
//! a host, or a service or user whose keytab is on it, deposits LUKS and
//! backup recovery keys into a seal whose depositor it is, with a ticket
//! from that keytab.  It seals them there and cannot open them again; the
//! seal's members can, under its policy.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use kuipa_enroll::seal::DepositKind;
use serde_json::Value;

use crate::paths::{Error, Paths};
use crate::seal::{SealClient, UserPaths};

fn host_dir(paths: &Paths) -> UserPaths {
    UserPaths::new(paths.escrow_dir())
}

/// Who deposits: the principal of `keytab`, or without one the host.
pub struct Depositor<'a> {
    /// The host.
    pub paths: &'a Paths,
    /// A service's or user's keytab, in place of the host's.
    pub keytab: Option<&'a Path>,
}

/// `kuipa escrow file NAME FILE --seal SEAL`: deposit `contents` as the
/// depositor's secret `name`, in place of its earlier one of that name.
///
/// # Errors
///
/// No enrolled host, a keytab of another realm, a refusal (not a
/// depositor), or any other error.
pub fn escrow_file(
    by: &Depositor<'_>,
    seal: &str,
    name: &str,
    contents: &[u8],
) -> Result<Value, Error> {
    let user = host_dir(by.paths);
    let subject = BTreeMap::from([("name".to_owned(), name.to_owned())]);
    SealClient::for_keytab(by.paths, &user, by.keytab).deposit(
        seal,
        contents,
        DepositKind::File,
        subject,
    )
}

/// `kuipa escrow luks DEVICE --seal SEAL`: deposit the recovery key in
/// `input` (as `systemd-cryptenroll --recovery-key DEVICE` prints it) for
/// the LUKS volume `device`, whose UUID is `uuid` or else what
/// `cryptsetup luksUUID` says, in place of the depositor's earlier deposit
/// for that volume.
///
/// # Errors
///
/// No recovery key in `input`, no UUID for the volume, a refusal, or any
/// other error.
pub fn escrow_luks(
    by: &Depositor<'_>,
    seal: &str,
    device: &str,
    input: &[u8],
    uuid: Option<&str>,
) -> Result<Value, Error> {
    let key = recovery_key(input)?;
    let uuid = match uuid {
        Some(u) => u.to_owned(),
        None => luks_uuid(device)?,
    };
    if uuid.len() != 36 || !uuid.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err(format!("{uuid:?} is not a LUKS UUID").into());
    }
    let user = host_dir(by.paths);
    let subject = BTreeMap::from([("uuid".to_owned(), uuid.to_ascii_lowercase())]);
    SealClient::for_keytab(by.paths, &user, by.keytab).deposit(
        seal,
        key.as_bytes(),
        DepositKind::Luks,
        subject,
    )
}

/// The modhex alphabet of systemd's recovery keys.
const MODHEX: &[u8] = b"cbdefghijklnrtuv";

/// The systemd recovery key in `input`: the line of eight groups of eight
/// modhex characters, whatever else `systemd-cryptenroll` printed around
/// it.
fn recovery_key(input: &[u8]) -> Result<String, Error> {
    let text = std::str::from_utf8(input).map_err(|_| "the recovery key is not text")?;
    text.lines()
        .map(str::trim)
        .find(|line| {
            let groups: Vec<&str> = line.split('-').collect();
            groups.len() == 8
                && groups
                    .iter()
                    .all(|g| g.len() == 8 && g.bytes().all(|b| MODHEX.contains(&b)))
        })
        .map(str::to_owned)
        .ok_or_else(|| {
            "no systemd recovery key in the input: pipe in `systemd-cryptenroll --recovery-key DEVICE`"
                .into()
        })
}

/// The UUID of the LUKS volume `device`, as `cryptsetup luksUUID` says.
fn luks_uuid(device: &str) -> Result<String, Error> {
    let out = Command::new("cryptsetup")
        .args(["luksUUID", device])
        .output()
        .map_err(|e| format!("cryptsetup luksUUID {device}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "cryptsetup luksUUID {device}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_recovery_key_is_found_among_what_cryptenroll_prints() {
        let key = "fejrltbu-bjitujnh-dfhrrbrk-hgbtdbgg-cbbitcrk-kclhkdgb-gbbhgjvb-ldbbrleb";
        let printed = format!(
            "A secret recovery key has been generated for this volume:\n\n    {key}\n\nPlease save this secret recovery key at a secure location.\n"
        );
        assert_eq!(recovery_key(printed.as_bytes()).unwrap(), key);
        assert!(recovery_key(b"no key here\n").is_err());
        // Wrong alphabet, or a group short.
        assert!(recovery_key(key.replace('f', "a").as_bytes()).is_err());
        assert!(recovery_key(&key.as_bytes()[..key.len() - 1]).is_err());
    }
}
