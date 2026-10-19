# Governance

Inveil is a small project with a simple structure. This page says who decides and how, so contributors know what to expect.

## Roles

- Users: anyone running Inveil. They report bugs and request features.
- Contributors: anyone who opens an issue, a pull request, a review or a documentation fix.
- Maintainers: people with write access who review and merge, cut releases and enforce the [Code of Conduct](CODE_OF_CONDUCT.md). The current maintainers are listed in [`.github/CODEOWNERS`](.github/CODEOWNERS).

## Decisions

- Most changes are decided in the pull request. A maintainer approves when the change is correct, tested, in scope and consistent with the [architecture](docs/ARCHITECTURE.md).
- Larger changes (new detector types, contract changes, new platform support, new dependencies, changes to the trust model) start as an issue. We use lazy consensus: if no maintainer objects within about a week, the proposal proceeds. Maintainers can ask for more discussion.
- Security-critical areas need a maintainer review and cannot be merged by their author alone: signing and verification, the updater, install scripts, the contract and the release pipeline.
- Contract changes follow the versioning rules in [docs/CONTRACT.md](docs/CONTRACT.md). Breaking changes need a new contract version, never a silent change to v1.
- If maintainers disagree, they discuss in the open on the issue. If they cannot agree, the lead maintainer decides and records the reason.

## Becoming a maintainer

Maintainers are invited by the existing maintainers after a sustained record of good contributions, sound reviews and care for security. Maintainers who stay inactive for a long time may be moved to emeritus status; they are always welcome back.

## Releases and keys

Maintainers cut releases following [docs/RELEASING.md](docs/RELEASING.md). Release signing keys are held by maintainers or in protected CI environments, never by a third party. Key changes are announced in the release notes.

## Conduct and disputes

The Code of Conduct applies everywhere the project operates. Reports go to the contact in that file. A maintainer who is the subject of a report does not take part in handling it.

## Changing this document

Changes to governance are proposed by pull request and need agreement of the maintainers.
