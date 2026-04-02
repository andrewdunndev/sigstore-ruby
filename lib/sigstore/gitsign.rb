# frozen_string_literal: true

# Copyright 2024 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "openssl"
require "json"
require_relative "models"
require_relative "verifier"
require_relative "trusted_root"
require_relative "policy"

module Sigstore
  # Gitsign verification support.
  #
  # Gitsign (https://github.com/sigstore/gitsign) signs git commits using
  # CMS/PKCS7 (RFC 5652) with Fulcio-issued short-lived certificates.
  # The signature is stored in the commit's `gpgsig` header as a PEM-encoded
  # PKCS7 detached signature.
  #
  # This module provides the glue between gitsign's CMS format and
  # sigstore-ruby's bundle-based verification, enabling Ruby applications
  # (such as GitLab) to verify gitsign-signed commits using the standard
  # Sigstore verification flow.
  module Gitsign
    class Error < Sigstore::Error; end
    class InvalidSignature < Error; end

    # Extracts the EncryptedDigest (raw signature bytes) from PKCS7 DER.
    # @param der [String] DER-encoded PKCS7
    # @return [String] raw signature bytes
    def self.extract_signature_from_pkcs7_der(der)
      asn1 = OpenSSL::ASN1.decode(der)
      # ContentInfo -> content (explicit tagged) -> SignedData
      signed_data = asn1.value[1].value[0]
      # SignedData -> last element is SignerInfos SET
      signer_infos = signed_data.value.last
      # SignerInfo -> last element is EncryptedDigest OCTET STRING
      signer_info = signer_infos.value.first
      signer_info.value.last.value
    end

    # Extracts the leaf certificate and signature from a gitsign CMS/PKCS7
    # detached signature.
    #
    # @param signature_pem [String] PEM-encoded PKCS7 signature from the
    #   git commit's gpgsig header
    # @return [Hash] with keys :certificate (OpenSSL::X509::Certificate),
    #   :signature (String, DER bytes), :all_certificates (Array)
    def self.parse_cms_signature(signature_pem)
      # gitsign wraps the PKCS7 in a custom header
      pem = signature_pem
        .sub(/^-----BEGIN SIGNED MESSAGE-----/, "-----BEGIN PKCS7-----")
        .sub(/^-----END SIGNED MESSAGE-----/, "-----END PKCS7-----")

      p7 = OpenSSL::PKCS7.new(pem)

      signers = p7.signers
      raise InvalidSignature, "Expected exactly one signer, got #{signers.size}" unless signers.size == 1

      certificates = p7.certificates
      raise InvalidSignature, "No certificates found in PKCS7 signature" if certificates.empty?

      # The leaf certificate is the signer's cert (first in the chain,
      # shortest validity period for Fulcio short-lived certs)
      leaf = certificates.min_by { |c| c.not_after - c.not_before }

      # Extract the raw signature (EncryptedDigest) from the PKCS7 ASN1
      # structure. Ruby's OpenSSL::PKCS7::SignerInfo doesn't expose the
      # signature bytes directly, so we parse the DER.
      #
      # PKCS7 ASN1 structure:
      #   ContentInfo -> SignedData -> SignerInfos -> SignerInfo -> EncryptedDigest
      signature_bytes = extract_signature_from_pkcs7_der(p7.to_der)

      {
        certificate: leaf,
        signature: signature_bytes,
        all_certificates: certificates
      }
    end

    # Detects whether a certificate was issued by Fulcio by checking for
    # the OIDC Issuer extension (OID 1.3.6.1.4.1.57264.1.1 or .1.8).
    #
    # @param cert [OpenSSL::X509::Certificate]
    # @return [Boolean]
    def self.fulcio_issued?(cert)
      cert.extensions.any? do |ext|
        ext.oid == "1.3.6.1.4.1.57264.1.1" || ext.oid == "1.3.6.1.4.1.57264.1.8"
      end
    end

    # Verifies a gitsign-signed git commit.
    #
    # @param signature_pem [String] the PEM PKCS7 signature from gpgsig header
    # @param signed_payload [String] the signed commit content (everything
    #   except the gpgsig header itself)
    # @param trust_root [Sigstore::TrustedRoot] trust root for verification
    # @param policy [Sigstore::Policy::Identity, etc.] identity policy
    # @param offline [Boolean] if true, skip Rekor lookup (requires bundle
    #   with inclusion proof)
    # @return [Sigstore::VerificationResult]
    def self.verify_commit(signature_pem:, signed_payload:, trust_root:, policy:, offline: false)
      parsed = parse_cms_signature(signature_pem)
      cert = parsed[:certificate]

      unless fulcio_issued?(cert)
        return VerificationFailure.new(
          "Certificate is not Fulcio-issued (missing OIDC issuer extension)"
        )
      end

      # Build a sigstore bundle from the CMS components
      cert_der = cert.to_der

      # For gitsign, the signature in the PKCS7 is over the commit content.
      # The Rekor entry is a hashedrekord keyed by SHA256 of the signed payload.
      payload_digest = OpenSSL::Digest::SHA256.digest(signed_payload)

      # Create a verifier from the trust root
      verifier = Verifier.for_trust_root(trust_root: trust_root)

      # Query Rekor for the matching entry.
      # Gitsign creates a hashedrekord entry with:
      #   - hash: SHA256 of the signed commit payload
      #   - signature: the raw signature from the PKCS7 SignerInfo
      #   - public key: the Fulcio leaf certificate PEM
      #
      # We construct the expected entry and search for it.
      expected_entry = {
        "spec" => {
          "signature" => {
            "content" => Internal::Util.base64_encode(parsed[:signature]),
            "publicKey" => {
              "content" => Internal::Util.base64_encode(cert.to_pem)
            }
          },
          "data" => {
            "hash" => {
              "algorithm" => "sha256",
              "value" => Internal::Util.hex_encode(payload_digest)
            }
          }
        },
        "kind" => "hashedrekord",
        "apiVersion" => "0.0.1"
      }

      begin
        entry = if offline
                  raise Error, "Offline verification not yet supported for gitsign commits"
                else
                  verifier.rekor_client.log.entries.retrieve.post(expected_entry)
                end
      rescue Sigstore::Error::FailedRekorLookup => e
        return VerificationFailure.new("Rekor entry not found for commit: #{e.message}")
      end

      # Now build a full VerificationInput protobuf
      bundle = Bundle::V1::Bundle.new
      bundle.media_type = BundleType::BUNDLE_0_3.media_type

      # Verification material: certificate + tlog entry
      bundle.verification_material = Bundle::V1::VerificationMaterial.new
      bundle.verification_material.certificate = Common::V1::X509Certificate.new
      bundle.verification_material.certificate.raw_bytes = cert_der
      bundle.verification_material.tlog_entries.push(entry)

      # Message signature
      bundle.message_signature = Common::V1::MessageSignature.new
      bundle.message_signature.signature = parsed[:signature]

      # Artifact (the signed commit payload)
      artifact = Verification::V1::Artifact.new
      artifact.artifact = signed_payload

      # Assemble the verification input
      input = Verification::V1::Input.new
      input.artifact_trust_root = trust_root.__getobj__
      input.bundle = bundle
      input.artifact = artifact

      verification_input = VerificationInput.new(input)
      verifier.verify(input: verification_input, policy: policy, offline: offline)
    end
  end
end
