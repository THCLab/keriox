# Controller

The Controller repository offers high-level functions that enable users to manage their own Key Event Log (KEL) and collect other identifier's KELs for verification purposes. To simplify the construction of complicated elements, the Controller repository utilizes serialized KERI events and basic types for crypto primitives as arguments. The library requires a third-party key provider that derives public-private key pairs and signatures.
## Usage

Most functions require a three step process to either establish new Identifier and its KEL or to append changes to the KEL. The process goes as following:

- prepare data for external signature;
- sign data;
- provide data along with signature.

### `Controller` structure
The `Controller` structure encapsulates logic for saving incoming KERI events and retrieving them from the database, as well as computing the current state of saved Identifiers. It also provides methods for generating new identifiers based on the provided public keys.

To create new `Controller`, path to database needs to be specified:
```rust
let root = Builder::new().prefix("test-db").tempdir().unwrap();

let controller = Arc::new(Controller::new(ControllerConfig {
	db_path: root.path().to_owned(),
	..Default::default()
})?);
```

### Establishing identifier

To establish an identifier, you need two sets of public keys - one for the current and one for the next. In our examples and tests, we utilize `CryptoBox` from `keriox_core` to generate them. To accomplish this, use the `incept` and `finalize_inception` functions:

```rust 
let mut km = CryptoBox::new()?;

// Incept identifier
let identifier1 = {
	let pk = BasicPrefix::Ed25519(km.public_key());
	let npk = BasicPrefix::Ed25519(km.next_public_key());

	let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
	let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(icp_event.as_bytes())?);

	let incept_identifier = controller
		.finalize_inception(icp_event.as_bytes(), &signature)
		.await?;
	IdentifierController::new(incept_identifier, controller.clone())
};
```
### Managing KEL

The `IdentifierController` structure combines the data stored in the `Controller` with a specific, already established identifier. Its main responsibility is to manage the concrete identifier's Key Event Log, which includes tasks such as generating events, publishing them to witnesses, and adding watchers. For example this is how you can rotate keys:

```rust
km.rotate()?;
let pk = BasicPrefix::Ed25519(km.public_key());
let npk = BasicPrefix::Ed25519(km.next_public_key());
let rotation_event = identifier1
	.rotate(vec![pk], vec![npk], vec![], vec![], 0)
	.await?;

let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(rotation_event.as_bytes())?);
identifier1
	.finalize_event(rotation_event.as_bytes(), signature)
	.await?;

```
For more examples checkout `components/controller/tests` folder.