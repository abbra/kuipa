//! [`Directory`] over 389-ds (LDAPI) and GSSAPI.
//!
//! * OTP joins bind as the host entry with the OTP and run the same join
//!   and `KEYTAB_GET` operations as `ipa-join` / `ipa-getkeytab -D -w`, so
//!   lockout, password policy and the one-time behaviour are unchanged.
//! * Password joins (password, password+OTP, RADIUS users) look up the
//!   user's entry and bind as it with the password, then join on that
//!   connection: the existing ACIs and authentication checks decide.
//! * Kerberos joins, rekeys and staging accept the client's GSS-API token
//!   with the exchange's channel binding, then act as the authenticated
//!   principal (S4U2Self + S4U2Proxy to LDAP), so the existing ACIs decide.
//! * Escrow bookkeeping uses the daemon's own identity.  Bindings live on
//!   the principal's entry: a host's by its FQDN, a service's or user's
//!   found by principal name under `cn=accounts` (§7.5).  Registration
//!   outside a rekey accepts the principal's own GSS-API token first.
//! * Anchor exchange syncs from other servers are accepted with the same
//!   credential; the sender must be `ipa-ku/<sender>` (§4.2).
//! * Voucher joins (§9), as the daemon once the voucher verified: add the
//!   host entry (as `ipa host-add` lays it out) with the spent salt in
//!   `ipaKUVoucherSpent`, so an existing host or a spent salt fails, add it
//!   to the voucher's host group, and create keys with `KEYTAB_GET`.
//! * Vaults (§7.6), as the daemon once the owner's ticket is accepted: one
//!   entry per vault under `cn=vaults,cn=kuipa,cn=etc,$SUFFIX` (owner, name,
//!   policy and devices as JSON, state), the realm limits as JSON on
//!   `cn=vault-limits,cn=kuipa,cn=etc,$SUFFIX`.
//! * Trusts (§17.4), as the daemon: invitations and partners are values on
//!   `cn=trusts,cn=kuipa,cn=etc,$SUFFIX`; an invitation is used up by
//!   deleting its exact value, which only one server can do.  The
//!   cross-realm `krbtgt` principals are added under
//!   `cn=$REALM,cn=kerberos,$SUFFIX` and given keys from the trust secret
//!   with `KEYTAB_GET` and a password, as `ipa-getkeytab -P` does.

use std::time::SystemTime;

use kuipa_enroll::escrow::{Kind, RegisterParams, VaultId};
use kuipa_enroll::join::{KERBEROS_BINDING_LEN, KerberosBinding, kerberos_prf_input};
use kuipa_enroll::keytab::{Enctype, Keytab, KeytabEntry, Principal};
use kuipa_enroll::server::Accepted;
use kuipa_enroll::server::{Directory, DirectoryError, Staged};
use kuipa_enroll::vault::{Device, Limits, State, Vault};
use kuipa_gssapi::{AcceptStep, GssClientCred, GssServerCred};
use kuipa_ldap::{Auth, LdapConnection, ModOp, Scope, SearchEntry, dn_escape, filter_escape};
use native_ossl::util::SecretBuf;

use crate::getkeytab::{self, JOIN_OID, KEYTAB_GET_OID};

/// Attribute holding registered escrow binding hashes (new schema).
const ESCROW_ATTR: &str = "ipaKUEscrowBinding";
/// Attribute holding the escrow binding hashes of sealed files (new
/// schema, §7.5).
const ESCROW_FILE_ATTR: &str = "ipaKUEscrowFileBinding";
/// Attribute recording staging (new schema), JSON.
const STAGED_ATTR: &str = "ipaKUStaged";

/// LDAP result code 16: the attribute to delete is not there.
const NO_SUCH_ATTRIBUTE: std::ffi::c_int = 16;
/// LDAP result code 32: the entry is not there.
const NO_SUCH_OBJECT: std::ffi::c_int = 32;
/// Spent voucher salts on created hosts (new schema).
const VOUCHER_SPENT_ATTR: &str = "ipaKUVoucherSpent";
/// Vault entries and their attributes (new schema, §7.6.2).
const VAULT_CLASS: &str = "ipaKUVault";
const VAULT_OWNER_ATTR: &str = "ipaKUVaultOwner";
const VAULT_NAME_ATTR: &str = "ipaKUVaultName";
const VAULT_POLICY_ATTR: &str = "ipaKUVaultPolicy";
const VAULT_DEVICE_ATTR: &str = "ipaKUVaultDevice";
const VAULT_STATE_ATTR: &str = "ipaKUVaultState";
/// Per-server release counts, `<server> <count>`, one value per server
/// (§7.6.7).
const VAULT_UNLOCKS_ATTR: &str = "ipaKUVaultUnlocks";
/// The realm's vault limits, JSON (new schema).
const VAULT_LIMITS_ATTR: &str = "ipaKUVaultLimits";
/// Trust invitations, `<hex secret hash> <not after>` (new schema).
const INVITATION_ATTR: &str = "ipaKUTrustInvitation";
/// Trusted realms, JSON (new schema).
const TRUSTED_ATTR: &str = "ipaKUTrustedRealm";

/// Daemon configuration for the directory side.
#[derive(Clone, Debug)]
pub struct Config {
    /// LDAPI URI, e.g. `ldapi://%2Frun%2Fslapd-EXAMPLE-TEST.socket`.
    pub ldap_uri: String,
    /// Base DN.
    pub basedn: String,
    /// Kerberos realm.
    pub realm: String,
    /// The daemon's principal, e.g. `ipa-ku/ipa1.example.test@EXAMPLE.TEST`.
    pub principal: String,
    /// GSS-API host-based service name, e.g. `ipa-ku@ipa1.example.test`.
    pub service: String,
    /// The daemon's keytab.
    pub keytab: String,
    /// PEM file with the IPA CA chain (`/etc/ipa/ca.crt`).
    pub ca_file: String,
    /// Enctypes the realm allows, strongest first.
    pub enctypes: Vec<Enctype>,
}

/// The LDAP-backed directory.
pub struct LdapDirectory {
    cfg: Config,
    server_cred: GssServerCred,
    /// Serialises use of the daemon's initiator ccache.
    initiator: std::sync::Mutex<()>,
}

impl LdapDirectory {
    /// Acquire the daemon's acceptor credential.
    ///
    /// # Errors
    ///
    /// A GSS-API error (keytab missing or unreadable, wrong principal).
    pub fn new(cfg: Config) -> Result<Self, DirectoryError> {
        let server_cred = GssServerCred::acquire(&cfg.service, &cfg.keytab)?;
        Ok(Self {
            cfg,
            server_cred,
            initiator: std::sync::Mutex::new(()),
        })
    }

    fn host_dn(&self, fqdn: &str) -> String {
        format!(
            "fqdn={},cn=computers,cn=accounts,{}",
            dn_escape(fqdn),
            self.cfg.basedn
        )
    }

    fn connect(&self) -> Result<LdapConnection, DirectoryError> {
        Ok(LdapConnection::connect(
            &self.cfg.ldap_uri,
            None,
            false,
            30,
        )?)
    }

    /// A connection bound as the daemon itself.  Requests run on several
    /// threads; its ccache is private and used by one of them at a time.
    fn service_conn(&self) -> Result<LdapConnection, DirectoryError> {
        let _guard = self
            .initiator
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cred = GssClientCred::from_keytab_initiate_named(
            &self.cfg.keytab,
            &self.cfg.principal,
            "MEMORY:kuipad-service",
        )?;
        let mut conn = self.connect()?;
        conn.bind_with_s4u_cred(&cred)?;
        Ok(conn)
    }

    /// Accept a one-leg GSS-API token bound to `cb`; return the principal
    /// and the binding the client's context derives too (§5.1).
    fn accept_bound(
        &self,
        token: &[u8],
        cb: &[u8; 32],
    ) -> Result<(String, KerberosBinding), DirectoryError> {
        let (principal, derived) = kuipa_gssapi::accept_bound(
            &self.server_cred,
            token,
            cb,
            &kerberos_prf_input(cb),
            KERBEROS_BINDING_LEN,
        )?;
        Ok((principal, KerberosBinding::new(&derived)?))
    }

    /// Accept a one-leg GSS-API token bound to `cb`; return the principal.
    fn accept(&self, token: &[u8], cb: &[u8; 32]) -> Result<String, DirectoryError> {
        match kuipa_gssapi::accept_token(&self.server_cred, token, Some(cb))? {
            AcceptStep::Complete { principal, .. } => Ok(principal),
            AcceptStep::Continue { .. } => Err("GSS-API exchange needs more than one token".into()),
        }
    }

    /// A connection bound as `principal`, through constrained delegation.
    fn conn_as(&self, principal: &str) -> Result<LdapConnection, DirectoryError> {
        let cred = kuipa_gssapi::impersonate_with_server_cred(&self.server_cred, principal)?;
        let mut conn = self.connect()?;
        conn.bind_with_s4u_cred(&cred)?;
        Ok(conn)
    }

    fn enctypes(&self, requested: &[Enctype]) -> Result<Vec<Enctype>, DirectoryError> {
        let chosen: Vec<_> = requested
            .iter()
            .copied()
            .filter(|e| self.cfg.enctypes.contains(e))
            .collect();
        if chosen.is_empty() {
            return Err("no allowed enctype requested".into());
        }
        Ok(chosen)
    }

    /// Run the join extended operation; returns the principal name.
    fn join(conn: &mut LdapConnection, fqdn: &str) -> Result<String, DirectoryError> {
        let result = conn.extended_operation(JOIN_OID, Some(fqdn.as_bytes()))?;
        let value = result.value.ok_or("join returned no principal")?;
        Ok(String::from_utf8(value)?.trim_end_matches('\0').to_owned())
    }

    /// Generate new keys for `principal` on the server.
    fn new_keys(
        &self,
        conn: &mut LdapConnection,
        principal: &str,
        requested: &[Enctype],
    ) -> Result<Keytab, DirectoryError> {
        let request = getkeytab::encode_new_keys(principal, &self.enctypes(requested)?)?;
        let result = conn.extended_operation(KEYTAB_GET_OID, Some(&request))?;
        let reply = result
            .controls
            .iter()
            .find(|(oid, _)| oid == KEYTAB_GET_OID)
            .ok_or("KEYTAB_GET returned no reply control")?;
        let reply = getkeytab::decode_reply(&reply.1)?;
        let timestamp =
            u32::try_from(tang_pqc::unix_seconds(SystemTime::now())).unwrap_or(u32::MAX);
        let principal: Principal = principal.parse()?;
        Ok(Keytab::new(
            principal,
            reply
                .keys
                .into_iter()
                .map(|k| KeytabEntry {
                    kvno: reply.kvno,
                    enctype: k.enctype,
                    key: k.key,
                    timestamp,
                })
                .collect(),
        ))
    }

    fn vaults_dn(&self) -> String {
        format!("cn=vaults,cn=kuipa,cn=etc,{}", self.cfg.basedn)
    }

    fn vault_dn(&self, id: &VaultId) -> String {
        format!("cn={id},{}", self.vaults_dn())
    }

    /// A vault from its entry.
    fn vault_from(entry: &kuipa_ldap::SearchEntry) -> Result<Vault, DirectoryError> {
        let one = |attr: &str| -> Result<String, DirectoryError> {
            entry
                .attrs
                .get(&attr.to_lowercase())
                .and_then(|v| v.first().cloned())
                .ok_or_else(|| format!("vault entry {} has no {attr}", entry.dn).into())
        };
        let id = entry
            .dn
            .strip_prefix("cn=")
            .and_then(|r| r.split(',').next())
            .ok_or("vault entry without cn")?
            .parse()?;
        let devices = entry
            .attrs
            .get(&VAULT_DEVICE_ATTR.to_lowercase())
            .into_iter()
            .flatten()
            .map(|d| serde_json::from_str::<Device>(d))
            .collect::<Result<_, _>>()?;
        let state = match one(VAULT_STATE_ATTR)?.as_str() {
            "enabled" => State::Enabled,
            _ => State::Revoked,
        };
        Ok(Vault {
            id,
            owner: one(VAULT_OWNER_ATTR)?,
            name: one(VAULT_NAME_ATTR)?,
            policy: serde_json::from_str(&one(VAULT_POLICY_ATTR)?)?,
            devices,
            state,
            unlocks: Self::unlock_counts(entry).iter().map(|(_, n)| n).sum(),
        })
    }

    /// The per-server release counts on a vault entry.
    fn unlock_counts(entry: &kuipa_ldap::SearchEntry) -> Vec<(String, u64)> {
        entry
            .attrs
            .get(&VAULT_UNLOCKS_ATTR.to_lowercase())
            .into_iter()
            .flatten()
            .filter_map(|v| {
                let (server, n) = v.rsplit_once(' ')?;
                Some((server.to_owned(), n.parse().ok()?))
            })
            .collect()
    }

    fn vault_attrs(vault: &Vault) -> Result<(String, Vec<String>, &'static str), DirectoryError> {
        let policy = serde_json::to_string(&vault.policy)?;
        let devices = vault
            .devices
            .iter()
            .map(serde_json::to_string)
            .collect::<Result<_, _>>()?;
        let state = match vault.state {
            State::Enabled => "enabled",
            State::Revoked => "revoked",
        };
        Ok((policy, devices, state))
    }

    fn trusts_dn(&self) -> String {
        format!("cn=trusts,cn=kuipa,cn=etc,{}", self.cfg.basedn)
    }

    /// The values of `attr` on the trusts entry.
    fn trust_values(&self, attr: &str) -> Result<Vec<String>, DirectoryError> {
        let entries = self.service_conn()?.search(
            &self.trusts_dn(),
            Scope::Base,
            "(objectClass=*)",
            &[attr],
        )?;
        Ok(entries
            .first()
            .and_then(|e| e.attrs.get(&attr.to_lowercase()).cloned())
            .unwrap_or_default())
    }

    /// Add `principal` (in this realm's container) unless it exists, and
    /// give it keys from `password`.
    fn cross_realm_principal(
        &self,
        conn: &mut LdapConnection,
        principal: &str,
        password: &[u8],
    ) -> Result<(), DirectoryError> {
        let dn = format!(
            "krbprincipalname={},cn={},cn=kerberos,{}",
            dn_escape(principal),
            dn_escape(&self.cfg.realm),
            self.cfg.basedn
        );
        let added = conn.add_s(
            &dn,
            &[
                (
                    "objectClass",
                    vec![
                        b"top".as_slice(),
                        b"krbPrincipal",
                        b"krbPrincipalAux",
                        b"krbTicketPolicyAux",
                    ],
                ),
                ("krbPrincipalName", vec![principal.as_bytes()]),
                ("krbCanonicalName", vec![principal.as_bytes()]),
            ],
        );
        if let Err(e) = added {
            // An existing principal (a renewed trust) gets new keys.
            if conn
                .search(&dn, Scope::Base, "(objectClass=krbPrincipal)", &["cn"])
                .map_or(true, |v| v.is_empty())
            {
                return Err(e.into());
            }
        }
        let request = getkeytab::encode_password_keys(principal, &self.cfg.enctypes, password)?;
        conn.extended_operation(KEYTAB_GET_OID, Some(request.as_ref()))?;
        Ok(())
    }

    fn host_principal(&self, fqdn: &str) -> String {
        Principal::host(fqdn, &self.cfg.realm).to_string()
    }

    /// The entry of `principal`, with `attrs`: a host's by its FQDN, any
    /// other principal's (services, users) by name under `cn=accounts`.
    fn principal_entry(
        &self,
        conn: &mut LdapConnection,
        principal: &Principal,
        attrs: &[&str],
    ) -> Result<Option<SearchEntry>, DirectoryError> {
        if let [service, fqdn] = principal.components()
            && service == "host"
        {
            let entries = conn.search(
                &self.host_dn(fqdn),
                Scope::Base,
                "(objectClass=ipaHost)",
                attrs,
            )?;
            return Ok(entries.into_iter().next());
        }
        let name = filter_escape(&principal.to_string());
        let entries = conn.search(
            &format!("cn=accounts,{}", self.cfg.basedn),
            Scope::Subtree,
            &format!("(|(krbPrincipalName={name})(krbCanonicalName={name}))"),
            attrs,
        )?;
        Ok(entries.into_iter().next())
    }
}

/// LDAP `GeneralizedTime` for Unix seconds.
#[allow(clippy::many_single_char_names)] // the textbook algorithm
fn generalized_time(t: u64) -> String {
    let days = t / 86400;
    let secs = t % 86400;
    // Civil-from-days (Howard Hinnant), valid for the Unix era.
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

impl Directory for LdapDirectory {
    fn join_with_otp(
        &self,
        fqdn: &str,
        otp: &[u8],
        enctypes: &[Enctype],
    ) -> Result<Keytab, DirectoryError> {
        let mut conn = self.connect()?;
        conn.bind(&Auth::Simple {
            bind_dn: self.host_dn(fqdn),
            password: SecretBuf::from_slice(otp),
        })?;
        let principal = Self::join(&mut conn, fqdn)?;
        self.new_keys(&mut conn, &principal, enctypes)
    }

    fn join_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        enctypes: &[Enctype],
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let (caller, binding) = self.accept_bound(token, cb)?;
        let mut conn = self.conn_as(&caller)?;
        let principal = Self::join(&mut conn, fqdn)?;
        Ok((self.new_keys(&mut conn, &principal, enctypes)?, binding))
    }

    fn rekey_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        enctypes: &[Enctype],
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let (caller, binding) = self.accept_bound(token, cb)?;
        let host = self.host_principal(fqdn);
        if caller != host {
            return Err(format!("{caller} may not rekey {host}").into());
        }
        let mut conn = self.conn_as(&caller)?;
        let keytab = self.new_keys(&mut conn, &host, enctypes)?;
        // First contact after offline enrollment: unstage (§8.5).
        let dn = self.host_dn(fqdn);
        let mut svc = self.service_conn()?;
        let entry = svc.search(&dn, Scope::Base, "(objectClass=*)", &[STAGED_ATTR])?;
        if entry
            .first()
            .is_some_and(|e| e.bin_attrs.contains_key(&STAGED_ATTR.to_lowercase()))
        {
            svc.modify_s(
                &dn,
                &[
                    (ModOp::Delete, STAGED_ATTR, Vec::new()),
                    (ModOp::Delete, "krbPrincipalExpiration", Vec::new()),
                ],
            )?;
            eprintln!("kuipad: first contact: {host} unstaged");
        }
        // First contact with an OTP-derived key (§5.3): the new keys replaced
        // it; the OTP must not work for an LDAP join either.
        match svc.modify_s(&dn, &[(ModOp::Delete, "userPassword", Vec::new())]) {
            Ok(()) => eprintln!("kuipad: first contact: {host}'s OTP consumed"),
            Err(kuipa_ldap::LdapError::Protocol {
                code: NO_SUCH_ATTRIBUTE,
                ..
            }) => {}
            Err(e) => return Err(e.into()),
        }
        Ok((keytab, binding))
    }

    fn stage_with_gss(
        &self,
        fqdn: &str,
        token: &[u8],
        cb: &[u8; 32],
        enctypes: &[Enctype],
        staged: &Staged,
    ) -> Result<(Keytab, KerberosBinding), DirectoryError> {
        let (caller, binding) = self.accept_bound(token, cb)?;
        let mut conn = self.conn_as(&caller)?;
        let host = self.host_principal(fqdn);
        // The host entry must exist (ipa host-add); joining it records
        // enrolledBy and sets the principal name, as ipa-join does.
        let principal = Self::join(&mut conn, fqdn).unwrap_or(host);
        let keytab = self.new_keys(&mut conn, &principal, enctypes)?;
        let record = serde_json::json!({
            "not_after": staged.not_after,
            "recipient": staged.recipient.map(|t| t.to_string()),
        })
        .to_string();
        let expiration = generalized_time(staged.not_after);
        conn.modify_s(
            &self.host_dn(fqdn),
            &[
                (ModOp::Replace, STAGED_ATTR, vec![record.as_bytes()]),
                (
                    ModOp::Replace,
                    "krbPrincipalExpiration",
                    vec![expiration.as_bytes()],
                ),
            ],
        )?;
        eprintln!("kuipad: {caller} staged {principal} until {expiration}");
        Ok((keytab, binding))
    }

    fn register_escrow(
        &self,
        principal: &Principal,
        bindings: &[[u8; 32]],
    ) -> Result<(), DirectoryError> {
        let mut svc = self.service_conn()?;
        let entry = self
            .principal_entry(&mut svc, principal, &["objectClass"])?
            .ok_or_else(|| format!("no entry for {principal}"))?;
        let values: Vec<&[u8]> = bindings.iter().map(<[u8; 32]>::as_slice).collect();
        svc.modify_s(&entry.dn, &[(ModOp::Replace, ESCROW_ATTR, values)])?;
        Ok(())
    }

    fn escrow_allowed(
        &self,
        principal: &Principal,
        kind: Kind,
        binding: &[u8; 32],
    ) -> Result<bool, DirectoryError> {
        let attr = match kind {
            Kind::Keytab => ESCROW_ATTR,
            Kind::File => ESCROW_FILE_ATTR,
        };
        let Some(entry) = self.principal_entry(
            &mut self.service_conn()?,
            principal,
            &[attr, "nsAccountLock"],
        )?
        else {
            return Ok(false);
        };
        let locked = entry
            .attrs
            .get("nsaccountlock")
            .is_some_and(|v| v.iter().any(|s| s.eq_ignore_ascii_case("true")));
        let registered = entry
            .bin_attrs
            .get(&attr.to_lowercase())
            .is_some_and(|v| v.iter().any(|b| b.as_slice() == binding));
        Ok(!locked && registered)
    }

    fn register_with_gss(
        &self,
        params: &RegisterParams,
        bindings: &[[u8; 32]],
        token: &[u8],
        cb: &[u8; 32],
    ) -> Result<KerberosBinding, DirectoryError> {
        let (caller, binding) = self.accept_bound(token, cb)?;
        let principal = &params.principal;
        if caller != principal.to_string() {
            return Err(
                format!("{caller} may not register escrow bindings for {principal}").into(),
            );
        }
        let mut svc = self.service_conn()?;
        let entry = self
            .principal_entry(&mut svc, principal, &["objectClass"])?
            .ok_or_else(|| format!("no entry for {principal}"))?;
        let values: Vec<&[u8]> = bindings.iter().map(<[u8; 32]>::as_slice).collect();
        match params.kind {
            Kind::Keytab => {
                svc.modify_s(&entry.dn, &[(ModOp::Replace, ESCROW_ATTR, values)])?;
            }
            Kind::File => {
                // One value at a time: a binding already gone is no error.
                for old in &params.retire {
                    match svc.modify_s(
                        &entry.dn,
                        &[(ModOp::Delete, ESCROW_FILE_ATTR, vec![old.as_slice()])],
                    ) {
                        Ok(())
                        | Err(kuipa_ldap::LdapError::Protocol {
                            code: NO_SUCH_ATTRIBUTE,
                            ..
                        }) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                if !values.is_empty() {
                    svc.modify_s(&entry.dn, &[(ModOp::Add, ESCROW_FILE_ATTR, values)])?;
                }
            }
        }
        eprintln!(
            "kuipad: {principal} registered {} {:?} escrow binding(s), retired {}",
            bindings.len(),
            params.kind,
            params.retire.len()
        );
        Ok(binding)
    }

    fn ca_certificates(&self) -> Result<Vec<Vec<u8>>, DirectoryError> {
        let out = synta_certificate::pem_to_der(&std::fs::read(&self.cfg.ca_file)?);
        if out.is_empty() {
            return Err(format!("no certificates in {}", self.cfg.ca_file).into());
        }
        Ok(out)
    }

    fn servers(&self) -> Result<Vec<String>, DirectoryError> {
        let base = format!("cn=masters,cn=ipa,cn=etc,{}", self.cfg.basedn);
        let entries =
            self.service_conn()?
                .search(&base, Scope::OneLevel, "(objectClass=*)", &["cn"])?;
        Ok(entries
            .into_iter()
            .filter_map(|e| e.attrs.get("cn").and_then(|v| v.first().cloned()))
            .collect())
    }

    fn accept_peer(&self, token: &[u8], cb: &[u8; 32]) -> Result<String, DirectoryError> {
        self.accept(token, cb)
    }

    fn accept_user(&self, token: &[u8], cb: &[u8; 32]) -> Result<Accepted, DirectoryError> {
        let (principal, binding) = self.accept_bound(token, cb)?;
        Ok(Accepted {
            principal,
            binding,
            // The PAC's delegation info is not read yet.
            transited: None,
        })
    }

    fn vault_limits(&self) -> Result<Limits, DirectoryError> {
        let dn = format!("cn=vault-limits,cn=kuipa,cn=etc,{}", self.cfg.basedn);
        let entries = match self.service_conn()?.search(
            &dn,
            Scope::Base,
            "(objectClass=*)",
            &[VAULT_LIMITS_ATTR],
        ) {
            Ok(e) => e,
            Err(kuipa_ldap::LdapError::Protocol {
                code: NO_SUCH_OBJECT,
                ..
            }) => return Ok(Limits::default()),
            Err(e) => return Err(e.into()),
        };
        match entries
            .first()
            .and_then(|e| e.attrs.get(&VAULT_LIMITS_ATTR.to_lowercase()))
            .and_then(|v| v.first())
        {
            Some(json) => Ok(serde_json::from_str(json)?),
            None => Ok(Limits::default()),
        }
    }

    fn vault_add(&self, vault: &Vault) -> Result<(), DirectoryError> {
        let (policy, devices, state) = Self::vault_attrs(vault)?;
        let id = vault.id.to_string();
        self.service_conn()?.add_s(
            &self.vault_dn(&vault.id),
            &[
                (
                    "objectClass",
                    vec![b"top".as_slice(), VAULT_CLASS.as_bytes()],
                ),
                ("cn", vec![id.as_bytes()]),
                (VAULT_OWNER_ATTR, vec![vault.owner.as_bytes()]),
                (VAULT_NAME_ATTR, vec![vault.name.as_bytes()]),
                (VAULT_POLICY_ATTR, vec![policy.as_bytes()]),
                (
                    VAULT_DEVICE_ATTR,
                    devices.iter().map(String::as_bytes).collect(),
                ),
                (VAULT_STATE_ATTR, vec![state.as_bytes()]),
            ]
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .collect::<Vec<_>>(),
        )?;
        eprintln!(
            "kuipad: {} created vault {id} ({})",
            vault.owner, vault.name
        );
        Ok(())
    }

    fn vault_get(&self, id: &VaultId) -> Result<Option<Vault>, DirectoryError> {
        match self.service_conn()?.search(
            &self.vault_dn(id),
            Scope::Base,
            &format!("(objectClass={VAULT_CLASS})"),
            &[
                VAULT_OWNER_ATTR,
                VAULT_NAME_ATTR,
                VAULT_POLICY_ATTR,
                VAULT_DEVICE_ATTR,
                VAULT_STATE_ATTR,
                VAULT_UNLOCKS_ATTR,
            ],
        ) {
            Ok(entries) => entries.first().map(Self::vault_from).transpose(),
            Err(kuipa_ldap::LdapError::Protocol {
                code: NO_SUCH_OBJECT,
                ..
            }) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn vault_update(&self, vault: &Vault) -> Result<(), DirectoryError> {
        let (policy, devices, state) = Self::vault_attrs(vault)?;
        self.service_conn()?.modify_s(
            &self.vault_dn(&vault.id),
            &[
                (ModOp::Replace, VAULT_POLICY_ATTR, vec![policy.as_bytes()]),
                (
                    ModOp::Replace,
                    VAULT_DEVICE_ATTR,
                    devices.iter().map(String::as_bytes).collect(),
                ),
                (ModOp::Replace, VAULT_STATE_ATTR, vec![state.as_bytes()]),
            ],
        )?;
        eprintln!(
            "kuipad: {} updated vault {} ({}): {state}, {} device(s)",
            vault.owner,
            vault.id,
            vault.name,
            devices.len()
        );
        Ok(())
    }

    fn vaults_of(&self, owner: &Principal) -> Result<Vec<Vault>, DirectoryError> {
        let filter = format!(
            "(&(objectClass={VAULT_CLASS})({VAULT_OWNER_ATTR}={}))",
            filter_escape(&owner.to_string())
        );
        let entries = match self.service_conn()?.search(
            &self.vaults_dn(),
            Scope::OneLevel,
            &filter,
            &[
                VAULT_OWNER_ATTR,
                VAULT_NAME_ATTR,
                VAULT_POLICY_ATTR,
                VAULT_DEVICE_ATTR,
                VAULT_STATE_ATTR,
                VAULT_UNLOCKS_ATTR,
            ],
        ) {
            Ok(e) => e,
            Err(kuipa_ldap::LdapError::Protocol {
                code: NO_SUCH_OBJECT,
                ..
            }) => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        entries.iter().map(Self::vault_from).collect()
    }

    fn vault_unlock(
        &self,
        id: &VaultId,
        server: &str,
        limit: Option<u64>,
    ) -> Result<bool, DirectoryError> {
        let mut svc = self.service_conn()?;
        let dn = self.vault_dn(id);
        let entries = svc.search(
            &dn,
            Scope::Base,
            &format!("(objectClass={VAULT_CLASS})"),
            &[VAULT_UNLOCKS_ATTR],
        )?;
        let entry = entries.first().ok_or("no such vault")?;
        let counts = Self::unlock_counts(entry);
        if limit.is_some_and(|l| counts.iter().map(|(_, n)| n).sum::<u64>() >= l) {
            return Ok(false);
        }
        // Only this server's value changes, so replicas never conflict:
        // the total is the sum of every server's own count.
        let own = counts.iter().find(|(s, _)| s == server).map(|(_, n)| *n);
        let old = own.map(|n| format!("{server} {n}"));
        let new = format!("{server} {}", own.unwrap_or(0) + 1);
        let mut mods = Vec::new();
        if let Some(old) = &old {
            mods.push((ModOp::Delete, VAULT_UNLOCKS_ATTR, vec![old.as_bytes()]));
        }
        mods.push((ModOp::Add, VAULT_UNLOCKS_ATTR, vec![new.as_bytes()]));
        svc.modify_s(&dn, &mods)?;
        Ok(true)
    }

    fn principal_locked(&self, principal: &Principal) -> Result<bool, DirectoryError> {
        let Some(entry) =
            self.principal_entry(&mut self.service_conn()?, principal, &["nsAccountLock"])?
        else {
            return Ok(true);
        };
        Ok(entry
            .attrs
            .get("nsaccountlock")
            .is_some_and(|v| v.iter().any(|s| s.eq_ignore_ascii_case("true"))))
    }

    fn join_with_voucher(
        &self,
        fqdn: &str,
        hostgroup: &str,
        salt: &[u8; 32],
        enctypes: &[Enctype],
    ) -> Result<Keytab, DirectoryError> {
        let mut conn = self.service_conn()?;
        let spent = hex(salt);
        let base = format!("cn=computers,cn=accounts,{}", self.cfg.basedn);
        let filter = format!("({VOUCHER_SPENT_ATTR}={})", filter_escape(&spent));
        if !conn
            .search(&base, Scope::OneLevel, &filter, &["fqdn"])?
            .is_empty()
        {
            return Err("spent voucher".into());
        }
        let principal = self.host_principal(fqdn);
        let short = fqdn.split('.').next().unwrap_or(fqdn);
        let dn = self.host_dn(fqdn);
        // Fails for an existing host.
        conn.add_s(
            &dn,
            &[
                (
                    "objectClass",
                    vec![
                        b"top".as_slice(),
                        b"ipaobject",
                        b"nshost",
                        b"ipahost",
                        b"pkiuser",
                        b"ipaservice",
                        b"ipasshhost",
                        b"ipaSshGroupOfPubKeys",
                        b"krbprincipalaux",
                        b"krbprincipal",
                        b"ieee802device",
                    ],
                ),
                ("fqdn", vec![fqdn.as_bytes()]),
                ("cn", vec![fqdn.as_bytes()]),
                ("serverHostName", vec![short.as_bytes()]),
                ("krbPrincipalName", vec![principal.as_bytes()]),
                ("krbCanonicalName", vec![principal.as_bytes()]),
                ("managedBy", vec![dn.as_bytes()]),
                ("ipaUniqueID", vec![b"autogenerate".as_slice()]),
                (VOUCHER_SPENT_ATTR, vec![spent.as_bytes()]),
            ],
        )?;
        if !hostgroup.is_empty() {
            conn.modify_s(
                &format!(
                    "cn={},cn=hostgroups,cn=accounts,{}",
                    dn_escape(hostgroup),
                    self.cfg.basedn
                ),
                &[(ModOp::Add, "member", vec![dn.as_bytes()])],
            )?;
        }
        eprintln!("kuipad: voucher created host {fqdn}");
        self.new_keys(&mut conn, &principal, enctypes)
    }

    fn add_trust_invitation(&self, hash: &[u8; 32], not_after: u64) -> Result<(), DirectoryError> {
        let value = format!("{} {not_after}", hex(hash));
        self.service_conn()?.modify_s(
            &self.trusts_dn(),
            &[(ModOp::Add, INVITATION_ATTR, vec![value.as_bytes()])],
        )?;
        Ok(())
    }

    fn consume_trust_invitation(&self, hash: &[u8; 32]) -> Result<(), DirectoryError> {
        let prefix = format!("{} ", hex(hash));
        let value = self
            .trust_values(INVITATION_ATTR)?
            .into_iter()
            .find(|v| v.starts_with(&prefix))
            .ok_or("unknown or used trust invitation")?;
        // Deleting the exact value fails for every server but one.
        self.service_conn()?
            .modify_s(
                &self.trusts_dn(),
                &[(ModOp::Delete, INVITATION_ATTR, vec![value.as_bytes()])],
            )
            .map_err(|_| "unknown or used trust invitation")?;
        let not_after: u64 = value[prefix.len()..].parse()?;
        if not_after <= tang_pqc::unix_seconds(SystemTime::now()) {
            return Err("expired trust invitation".into());
        }
        Ok(())
    }

    fn record_trust(
        &self,
        partner: &kuipa_enroll::realm::TrustedRealm,
        secret: &[u8],
    ) -> Result<(), DirectoryError> {
        let password = kuipa_enroll::trust::secret_text(&SecretBuf::from_slice(secret));
        let mut conn = self.service_conn()?;
        for principal in [
            format!("krbtgt/{}@{}", partner.realm, self.cfg.realm),
            format!("krbtgt/{}@{}", self.cfg.realm, partner.realm),
        ] {
            self.cross_realm_principal(&mut conn, &principal, password.as_ref())?;
        }
        eprintln!("kuipad: cross-realm keys for {} created", partner.realm);
        self.update_or_add(&mut conn, partner)
    }

    fn update_trust(
        &self,
        partner: &kuipa_enroll::realm::TrustedRealm,
    ) -> Result<(), DirectoryError> {
        let mut conn = self.service_conn()?;
        self.update_or_add(&mut conn, partner)
    }

    fn trusted_realms(&self) -> Result<Vec<kuipa_enroll::realm::TrustedRealm>, DirectoryError> {
        Ok(self
            .trust_values(TRUSTED_ATTR)?
            .iter()
            .filter_map(|v| kuipa_enroll::realm::TrustedRealm::from_json(v.as_bytes()).ok())
            .collect())
    }
}

impl LdapDirectory {
    /// Replace `partner`'s value on the trusts entry, or add it.
    fn update_or_add(
        &self,
        conn: &mut LdapConnection,
        partner: &kuipa_enroll::realm::TrustedRealm,
    ) -> Result<(), DirectoryError> {
        let old: Vec<String> = self
            .trust_values(TRUSTED_ATTR)?
            .into_iter()
            .filter(|v| {
                kuipa_enroll::realm::TrustedRealm::from_json(v.as_bytes())
                    .is_ok_and(|t| t.realm.eq_ignore_ascii_case(&partner.realm))
            })
            .collect();
        let new = partner.to_json();
        let mut mods = Vec::new();
        if !old.is_empty() {
            mods.push((
                ModOp::Delete,
                TRUSTED_ATTR,
                old.iter().map(String::as_bytes).collect(),
            ));
        }
        mods.push((ModOp::Add, TRUSTED_ATTR, vec![new.as_bytes()]));
        conn.modify_s(&self.trusts_dn(), &mods)?;
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_time_formats() {
        assert_eq!(generalized_time(0), "19700101000000Z");
        assert_eq!(generalized_time(1_800_000_000), "20270115080000Z");
        assert_eq!(generalized_time(951_782_400), "20000229000000Z");
    }
}
