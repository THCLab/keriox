use keri_core::{
    event::sections::threshold::SignatureThreshold,
    event_message::{event_msg_builder::EventMsgBuilder, EventTypeTag},
    prefix::{BasicPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use tempfile::{Builder, TempDir};

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError,
    identifier::mechanics::MechanicsError, Abandonment, RedbIdentifier,
};

/// An identifier with no witnesses, incepted with `km`'s keys.
async fn incept(km: &CryptoBox) -> Result<(TempDir, RedbIdentifier), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?;
    let inception_event = controller
        .incept(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            vec![],
            0,
        )
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(inception_event.as_bytes())?);
    let identifier = controller.finalize_incept(inception_event.as_bytes(), &signature)?;
    Ok((root, identifier))
}

/// Abandons `identifier` by revealing `km`'s next key. Returns the
/// abandonment event.
async fn abandon(
    identifier: &mut RedbIdentifier,
    km: &mut CryptoBox,
) -> Result<String, ControllerError> {
    km.rotate()?;
    let event = identifier
        .abandon(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![],
            vec![],
            0,
            vec![],
        )
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(event.as_bytes())?);
    identifier
        .finalize_rotate(event.as_bytes(), signature)
        .await?;
    Ok(event)
}

#[async_std::test]
async fn an_abandoned_identifier_is_final() -> Result<(), ControllerError> {
    let mut km = CryptoBox::new()?;
    let (_root, mut identifier) = incept(&km).await?;
    assert!(!identifier.is_abandoned());

    abandon(&mut identifier, &mut km).await?;

    assert!(identifier.is_abandoned());
    let state = identifier.find_state(identifier.id())?;
    assert_eq!(state.sn, 1);
    assert!(state.current.next_keys_data.is_empty());
    assert_eq!(
        identifier.find_status(identifier.id())?.abandoned,
        Some(Abandonment {
            sn: 1,
            said: state.last_event_digest.said.clone()
        })
    );

    let rotation = identifier
        .rotate(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            1,
            vec![],
            vec![],
            0,
        )
        .await;
    assert!(matches!(
        rotation,
        Err(MechanicsError::IdentifierAbandoned(id)) if &id == identifier.id()
    ));
    assert!(matches!(
        identifier.anchor(&[]),
        Err(MechanicsError::IdentifierAbandoned(_))
    ));
    assert!(matches!(
        identifier
            .abandon(
                vec![BasicPrefix::Ed25519(km.public_key())],
                vec![],
                vec![],
                0,
                vec![]
            )
            .await,
        Err(MechanicsError::IdentifierAbandoned(_))
    ));

    Ok(())
}

#[async_std::test]
async fn a_rotation_reaching_an_abandoned_identifier_errors_instead_of_panicking(
) -> Result<(), ControllerError> {
    let mut km = CryptoBox::new()?;
    let (_root, mut identifier) = incept(&km).await?;
    let abandonment = abandon(&mut identifier, &mut km).await?;
    let previous = identifier
        .find_state(identifier.id())?
        .last_event_digest
        .said;
    assert!(abandonment.contains(&previous.to_string()));

    // A rotation built outside the generators, revealing a key this
    // identifier never held: finding its own position in it used to index
    // into the empty next key list.
    let stranger = CryptoBox::new()?;
    let rotation = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(identifier.id())
        .with_sn(2)
        .with_previous_event(&previous)
        .with_keys(vec![BasicPrefix::Ed25519(stranger.public_key())])
        .with_next_keys(vec![BasicPrefix::Ed25519(stranger.next_public_key())])
        .with_next_threshold(&SignatureThreshold::Simple(1))
        .build()
        .unwrap()
        .encode()
        .unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(stranger.sign(&rotation)?);

    assert!(matches!(
        identifier.finalize_rotate(&rotation, signature).await,
        Err(MechanicsError::IdentifierAbandoned(_))
    ));
    assert_eq!(identifier.find_state(identifier.id())?.sn, 1);

    Ok(())
}
