# Overview

Rust based implementation of the [IETF Draft Public Transaction Event Logs (PTEL) specification](https://weboftrust.github.io/ietf-ptel/draft-pfeairheller-ptel.html). TEL is a state machine, where any state change of this statee machine is represented as append only, end-verifiable log that derives its foundations from Event Sourcing and adds cryptographic authenticity on top of that.

TEL proposed here is a issuance revocation state machine, which constists of three states:
* `NULL` -- given member does not exist yet in the registry;
* `issued` -- given member declares it is present/issued;
* `revoked` -- given member declares it is removed/revoked.


## License

EUPL 1.2 

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).
