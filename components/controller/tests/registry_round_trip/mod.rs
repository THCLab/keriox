//! The registry round trip both storage backends must pass.

use keri_controller::{
    controller::Controller,
    error::ControllerError,
    registry::{AcdcBinding, Blinding, Policy, Verdict},
    BasicPrefix, CryptoBox, KeyManager, SelfSigningPrefix,
};
use keri_core::{
    actor::prelude::{HashFunction, HashFunctionCode},
    database::{EscrowCreator, EventDatabase},
    oobi_manager::storage::OobiStorageBackend,
};
use teliox::registry::RegistryStore;

/// An identifier without witnesses runs a private registry: it incepts the
/// registry and issues a credential in one anchor, judges its own disclosure
/// valid and issued, revokes it, and then judges the kept registry revoked.
pub async fn issue_and_revoke<D, T, S>(
    controller: &Controller<D, T, S>,
) -> Result<(), ControllerError>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    let km = CryptoBox::new()?;
    let icp = controller
        .incept(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            vec![],
            0,
        )
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(icp.as_bytes())?);
    let mut issuer = controller.finalize_incept(icp.as_bytes(), &signature)?;
    let sign = |ixn: &[u8]| SelfSigningPrefix::Ed25519Sha512(km.sign(ixn).unwrap());

    let rip = issuer.incept_registry()?;
    let registry = rip.event.said().unwrap();

    let blinding = Blinding::private();
    let acdc = HashFunction::from(HashFunctionCode::Blake3_256).derive(b"credential");
    let presented = AcdcBinding {
        said: acdc.clone(),
        issuer: issuer.id().clone(),
        registry: Some(registry.clone()),
    };
    let policy = Policy::default();

    let (issued, ixn) = issuer.issue_in(rip, &blinding, &acdc)?;
    let ixn = ixn.encode()?;
    issuer
        .finalize_registry_events(&issued, &ixn, sign(&ixn))
        .await
        .unwrap();
    let disclosure = issuer.registry_disclosure(&registry)?;
    match issuer.accept_disclosure(&disclosure, Some(&presented), &policy)? {
        Verdict::Valid { state, .. } => assert_eq!(state.state.as_deref(), Some("issued")),
        other => panic!("{other:?}"),
    }

    let (revoked, ixn) = issuer.revoke(&registry, &blinding, &acdc)?;
    let ixn = ixn.encode()?;
    issuer
        .finalize_registry_events(&revoked, &ixn, sign(&ixn))
        .await
        .unwrap();
    match issuer.registry_verdict(&registry, Some(&presented), &policy)? {
        Verdict::Valid { state, .. } => {
            assert_eq!((state.sn, state.state.as_deref()), (2, Some("revoked")))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(issuer.find_state(issuer.id())?.sn, 2);
    Ok(())
}
