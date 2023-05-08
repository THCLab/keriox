# Controller

The Controller repository offers high-level functions that enable users to manage Key Event Log (KEL) and collect other identifiers' KELs for verification purposes. The library requires a third-party key provider that derives public-private key pairs and signatures.

## Usage

Most functions require a three step process to either establish new Identifier and its KEL or to append changes to the KEL. The process goes as following:

- prepare data for external signature;
- sign data;
- provide data along with signature.

### `Controller` structure

The `Controller` structure encapsulates logic for saving incoming KERI events and retrieving them from the database, as well as computing the current state of saved Identifiers. It also provides methods for generating new identifiers based on the provided public keys (`incept` and `finalize_inception`).
### Managing KEL

The `IdentifierController` structure combines the data stored in the `Controller` with a specific, already established identifier. Its main responsibility is to manage the concrete identifier's Key Event Log, which includes tasks such as generating events, publishing them to witnesses, and adding watchers.

For examples checkout `components/controller/tests` folder.