//! An enrollment server on a local port: the pieces every test that needs
//! one builds the same way.

#![allow(dead_code)]
use std::sync::Arc;

use kuipa_enroll::EnrollServer;
use kuipa_enroll::delegation::Delegation;
use kuipa_enroll::realm::{RealmInfo, ServerKeys};
use kuipad::http::{App, router};
use tang_pqc::{ExchangeKeyPair, KemAlg, SignatureAlg, SigningKey, VerifyingKey, now};

/// A fresh anchor, and the server `info.server` it delegates to; `info`
/// gets the anchor.  The server takes `vouchers` and, with `trust`, a key
/// for trust invitations.
pub(crate) fn enroll_server(
    mut info: RealmInfo,
    trust: bool,
    vouchers: Vec<VerifyingKey>,
    days: u64,
) -> (SigningKey, Arc<EnrollServer>) {
    let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
    let delegation = Delegation::issue(
        &anchor,
        &info.realm,
        &info.server,
        signing.public(),
        now() - 60,
        now() + days * 86400,
    )
    .unwrap();
    info.anchors = vec![*anchor.public().thumbprint()];
    info.validate().unwrap();
    let kem = || ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
    let keys = ServerKeys {
        signing,
        join: vec![kem()],
        escrow: vec![kem()],
        trust: if trust { vec![kem()] } else { Vec::new() },
        vouchers,
        retired: Vec::new(),
    };
    (anchor, Arc::new(EnrollServer::new(keys, info, delegation)))
}

/// Serve `app` on `listener` in a background runtime.
pub(crate) fn serve(listener: std::net::TcpListener, app: Arc<App>) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    listener.set_nonblocking(true).unwrap();
    std::thread::spawn(move || {
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(listener, router(app)).await.unwrap();
        });
    });
}

/// Serve `app` on a free local port; its URL.
pub(crate) fn spawn(app: Arc<App>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    serve(listener, app);
    url
}
