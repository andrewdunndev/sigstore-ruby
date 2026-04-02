# Sigstore

This is a pure Ruby implementation of the `sigstore verify` command from the [sigstore/cosign](https://sigstore.dev/projects/cosign) project. It is intended to be used as a library in other Ruby projects or directly through a new `gem` subcommand. The project also contains a TUF client implementation, given TUF is a part of the sigstore verification flow.

## Usage

```shell
$ gem sigstore_cosign_verify_bundle --bundle a.txt.sigstore \
    --certificate-identity https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    a.txt
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test-unit` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Ruby API

### Verification

The primary use case is verifying sigstore bundles programmatically:

```ruby
require "sigstore"

# Using the public Sigstore trust root (fetched via TUF)
verifier = Sigstore::Verifier.production

# Or, for a self-hosted Sigstore deployment
trust_root = Sigstore::TrustedRoot.from_file("/path/to/trusted_root.json")
verifier = Sigstore::Verifier.for_trust_root(trust_root: trust_root)

# Verify a bundle
input = Sigstore::VerificationInput.new(verification_input_proto)
policy = Sigstore::Policy::Identity.new(
  identity: "user@example.com",
  issuer: "https://accounts.google.com"
)
result = verifier.verify(input: input, policy: policy, offline: false)
result.verified? # => true
result.reason    # => nil (only set on failure)
```

The `verify` method returns a `Sigstore::VerificationResult`. On success it returns a `Sigstore::VerificationSuccess` (`verified?` is `true`). On failure it returns a `Sigstore::VerificationFailure` (`verified?` is `false`, `reason` contains the error message).

There is also a `Verifier.staging` constructor for the Sigstore staging environment.

### Gitsign Commit Verification

The `Sigstore::Gitsign` module verifies git commits signed with [gitsign](https://github.com/sigstore/gitsign). Gitsign uses CMS/PKCS7 detached signatures with Fulcio-issued short-lived certificates, and records signing events in Rekor.

```ruby
require "sigstore/gitsign"

trust_root = Sigstore::TrustedRoot.from_file("trusted_root.json")
policy = Sigstore::Policy::Identity.new(
  identity: "user@example.com",
  issuer: "https://accounts.google.com"
)

result = Sigstore::Gitsign.verify_commit(
  signature_pem: pkcs7_pem,     # PEM from git's gpgsig header
  commit_sha: "abc123def456...", # Full commit SHA hex string
  trust_root: trust_root,
  policy: policy
)

if result.verified?
  puts "Commit signature valid"
else
  puts "Verification failed: #{result.reason}"
end
```

The module handles the translation between gitsign's CMS format and the standard Sigstore verification flow:

1. Parses the PKCS7 signature to extract the Fulcio leaf certificate
2. Searches Rekor for the corresponding `hashedrekord` entry (by SHA-256 of the commit SHA)
3. Builds a Sigstore bundle from the Rekor entry
4. Verifies the bundle through the standard `Sigstore::Verifier` pipeline

You can also use the lower-level helpers directly:

```ruby
# Parse a CMS signature without verifying
parsed = Sigstore::Gitsign.parse_cms_signature(pkcs7_pem)
parsed[:certificate]      # => OpenSSL::X509::Certificate (leaf)
parsed[:signature]        # => String (raw signature bytes)
parsed[:all_certificates] # => Array of OpenSSL::X509::Certificate

# Check if a certificate was issued by Fulcio
Sigstore::Gitsign.fulcio_issued?(parsed[:certificate]) # => true/false
```

### Self-hosted Sigstore

For environments running self-hosted Fulcio, Rekor, and CT Log (e.g., airgapped or controlled-egress deployments), you need a `trusted_root.json` that describes your infrastructure.

**Loading a custom trust root:**

```ruby
# From a local file
trust_root = Sigstore::TrustedRoot.from_file("/path/to/trusted_root.json")

# From a TUF repository
trust_root = Sigstore::TrustedRoot.from_tuf("https://tuf.example.com", false)
```

The `trusted_root.json` file follows the [Sigstore TrustedRoot protobuf schema](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_trustroot.proto) and must contain:

- **Certificate authorities** -- your Fulcio CA certificate chain
- **Transparency logs** -- your Rekor public key and base URL
- **CT logs** -- your Certificate Transparency log public keys
- **Timestamp authorities** (optional) -- if using RFC 3161 timestamps

**HTTP vs HTTPS:** The Rekor client correctly handles both `http://` and `https://` URLs based on the scheme in your trust root's `base_url` field. This is important for self-hosted deployments that may run Rekor behind a cluster-internal HTTP endpoint (e.g., `http://rekor.sigstore-system.svc`).

### Policy Classes

Policies determine which signing identities are accepted during verification.

| Class | Description |
|-------|-------------|
| `Sigstore::Policy::Identity` | Matches a specific identity (SAN) and OIDC issuer. This is the most common policy. |
| `Sigstore::Policy::OIDCIssuer` | Matches only the OIDC issuer extension (OID `1.3.6.1.4.1.57264.1.1`). |
| `Sigstore::Policy::OIDCIssuerV2` | Matches the v2 OIDC issuer extension (OID `1.3.6.1.4.1.57264.1.8`) with DER-encoded value. |
| `Sigstore::Policy::AnyOf` | Accepts a certificate if any of the provided sub-policies match. |

```ruby
# Require a specific user from a specific issuer
policy = Sigstore::Policy::Identity.new(
  identity: "user@example.com",
  issuer: "https://accounts.google.com"
)

# Accept any identity from a GitHub Actions workflow
policy = Sigstore::Policy::OIDCIssuer.new("https://token.actions.githubusercontent.com")

# Accept certificates from multiple issuers
policy = Sigstore::Policy::AnyOf.new(
  Sigstore::Policy::OIDCIssuer.new("https://accounts.google.com"),
  Sigstore::Policy::OIDCIssuer.new("https://token.actions.githubusercontent.com")
)
```

Note: `Identity` internally uses `AnyOf` to check both v1 and v2 OIDC issuer extensions.

### Bundle Types

The gem supports the following Sigstore bundle media types:

| Version | Media Type |
|---------|-----------|
| 0.1 | `application/vnd.dev.sigstore.bundle+json;version=0.1` |
| 0.2 | `application/vnd.dev.sigstore.bundle+json;version=0.2` |
| 0.3 | `application/vnd.dev.sigstore.bundle+json;version=0.3` |

Bundle version 0.3 is the current default for new signatures. Older bundles (0.1 and 0.2) are accepted during verification for backwards compatibility.

## Contributing

Bug reports and pull requests are welcome on GitHub at <https://github.com/sigstore/sigstore-ruby>.

## License

The gem is available as open source under the terms of the [Apache 2](https://opensource.org/licenses/Apache-2.0).
