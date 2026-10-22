# Documentation

## Using OBDCracker

- [Install](install.md): one-command install on Windows, macOS and Linux
- [Using the CLI](usage.md): `adapter`, `fingerprint`, `scan`, `sweep` and their options
- [Using it as a library](library.md): importing the `obdcracker` crate
- [Safety model](safety.md): the policy, tiers, backups, dry runs and the audit log

## Reference

- [Adapters](adapters.md): supported adapter drivers and links
- [Protocols](protocols.md): physical, transport and diagnostic protocol status
- [Vehicle profiles](profiles.md): what a profile holds, and the profiles so far
- [Scanning](scanning.md): module discovery, DID batching, the extended session and sweeps
- [VW TP2.0](tp20.md): TP2.0 frames, ACKs, keep-alive, channel setup and disconnect
- [ELM327 notes](elm327.md): the adapter behaviour the `elm` driver relies on, with datasheet pages

## Contributing

- [Contributing](CONTRIBUTING.md): how changes land, issues, reviews and commits
- [Development](development.md): crate layout and checks
- [Pitfalls](pitfalls.md): classes of bug reviews have caught; read before making a change
- [Third-party test data](third-party.md): outside sources used in tests, and their licenses
