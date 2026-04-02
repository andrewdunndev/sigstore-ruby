## [Unreleased]

### Added

- Gitsign commit signature verification (`Sigstore::Gitsign`) -- verifies git
  commits signed with [gitsign](https://github.com/sigstore/gitsign) by
  translating CMS/PKCS7 detached signatures into Sigstore bundles and running
  them through the standard verification pipeline.
  See [#303](https://github.com/sigstore/sigstore-ruby/issues/303).
- Ruby API documentation in README covering verification, gitsign, self-hosted
  Sigstore, policy classes, and bundle types.

### Fixed

- Rekor client now correctly handles plain HTTP URLs (`http://`) for
  self-hosted deployments that run Rekor behind cluster-internal endpoints
  without TLS.

## [0.1.1] - 2024-10-18

- Fix release automation

## [0.1.0] - 2024-10-18

- Initial release
