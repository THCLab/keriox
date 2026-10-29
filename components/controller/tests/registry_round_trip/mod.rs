//! The registry round trip both storage backends must pass.

use keri_controller::{
    controller::Controller,
    error::ControllerError,
    registry::{AcdcBinding, Blinding, Policy, Presentation, Verdict},
    BasicPrefix, CryptoBox, KeyManager, SelfSigningPrefix,
};
use keri_core::{
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
    let credential = acdc::Acdc::builder(
        issuer.id().to_string(),
        "EOlgQaGgXI6Zqikg4I0KWaQeL9sRUGu7PUj78GekKnSf",
    )
    .private()
    .registry(registry.to_string())
    .attributes(acdc::Block::new().with("degree", "MSc"))
    .build(acdc::Kind::Json, acdc::HashFunctionCode::Blake3_256)
    .unwrap();
    let acdc: said::SelfAddressingIdentifier = credential.said().parse().unwrap();
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

    // The issuer grants the credential to a holder, who judges it and
    // admits it.
    let holder_keys = CryptoBox::new()?;
    let icp = controller
        .incept(
            vec![BasicPrefix::Ed25519(holder_keys.public_key())],
            vec![BasicPrefix::Ed25519(holder_keys.next_public_key())],
            vec![],
            0,
        )
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(holder_keys.sign(icp.as_bytes())?);
    let holder = controller.finalize_incept(icp.as_bytes(), &signature)?;
    let presentation = Presentation {
        acdc: credential,
        disclosure,
    };
    let grant = issuer.grant(holder.id(), "Your diploma", &presentation);
    let grant_sig = sign(&grant.signing_bytes().unwrap());
    let stream = issuer.finalize_grant(grant, &presentation, grant_sig)?;
    let (grant, received, verdict) = holder.receive_grant(&stream, &policy)?;
    assert_eq!(received, presentation);
    match verdict {
        Verdict::Valid { state, .. } => assert_eq!(state.state.as_deref(), Some("issued")),
        other => panic!("{other:?}"),
    }
    assert_eq!(grant.message(), Some("Your diploma"));
    assert!(issuer.receive_grant(&stream, &policy).is_err());
    let admit = holder.admit(&grant, "Thanks")?;
    let admit_sig =
        SelfSigningPrefix::Ed25519Sha512(holder_keys.sign(&admit.signing_bytes().unwrap())?);
    let admit = holder.finalize_admit(admit, admit_sig)?;
    let admitted = issuer.receive_admit(&admit)?;
    assert_eq!(admitted.grant().unwrap(), grant.exchange.digest().unwrap());

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
