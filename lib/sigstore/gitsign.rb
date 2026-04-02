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
    # @param commit_sha [String] the git commit SHA (hex string)
    # @param trust_root [Sigstore::TrustedRoot] trust root for verification
    # @param policy [Sigstore::Policy::Identity, etc.] identity policy
    # @param offline [Boolean] if true, skip Rekor lookup (requires bundle
    #   with inclusion proof)
    # @return [Sigstore::VerificationResult]
    def self.verify_commit(signature_pem:, commit_sha:, trust_root:, policy:, offline: false)
      parsed = parse_cms_signature(signature_pem)
      cert = parsed[:certificate]

      unless fulcio_issued?(cert)
        return VerificationFailure.new(
          "Certificate is not Fulcio-issued (missing OIDC issuer extension)"
        )
      end

      cert_der = cert.to_der

      # Create a verifier from the trust root
      verifier = Verifier.for_trust_root(trust_root: trust_root)

      # Gitsign creates a hashedrekord entry where:
      #   - hash: SHA256 of the commit SHA hex string (NOT the signed payload)
      #   - signature: a fresh ECDSA signature (NOT the CMS signature)
      #   - public key: the Fulcio leaf certificate PEM
      #
      # We search Rekor by hash to find the entry, then verify the entry
      # contains a certificate matching the one in our PKCS7 signature.
      commit_sha_hex_digest = OpenSSL::Digest::SHA256.hexdigest(commit_sha)

      begin
        entry = if offline
                  raise Error, "Offline verification not yet supported for gitsign commits"
                else
                  search_rekor_by_hash(verifier.rekor_client, commit_sha_hex_digest, cert)
                end
      rescue Error => e
        return VerificationFailure.new("Rekor entry not found: #{e.message}")
      end

      # Build a bundle with the Rekor entry for verification
      bundle = Bundle::V1::Bundle.new
      bundle.media_type = BundleType::BUNDLE_0_3.media_type

      bundle.verification_material = Bundle::V1::VerificationMaterial.new
      bundle.verification_material.certificate = Common::V1::X509Certificate.new
      bundle.verification_material.certificate.raw_bytes = cert_der
      bundle.verification_material.tlog_entries.push(entry)

      # The message signature in the Rekor entry (NOT the CMS signature)
      rekor_body = JSON.parse(entry.canonicalized_body)
      rekor_sig_b64 = rekor_body.dig("spec", "signature", "content")
      rekor_sig = Internal::Util.base64_decode(rekor_sig_b64)

      bundle.message_signature = Common::V1::MessageSignature.new
      bundle.message_signature.signature = rekor_sig

      # The artifact is the commit SHA hex string (what was hashed for Rekor)
      artifact = Verification::V1::Artifact.new
      artifact.artifact = commit_sha

      input = Verification::V1::Input.new
      input.artifact_trust_root = trust_root.__getobj__
      input.bundle = bundle
      input.artifact = artifact

      verification_input = VerificationInput.new(input)
      verifier.verify(input: verification_input, policy: policy, offline: offline)
    end

    # Searches Rekor for a hashedrekord entry matching the commit SHA.
    # Returns the decoded tlog entry, or raises Error if not found.
    def self.search_rekor_by_hash(rekor_client, sha256_hex, expected_cert)
      # Access the Rekor client's HTTP session and base URL
      # The client stores @url as "http://rekor.example/api/v1/"
      client_url = rekor_client.instance_variable_get(:@url)
      session = rekor_client.instance_variable_get(:@session)

      # Search Rekor index by hash
      index_url = URI.join(client_url, "index/retrieve")
      data = { "hash" => "sha256:#{sha256_hex}" }
      resp = session.post2(index_url.path, data.to_json,
                           { "Content-Type" => "application/json", "Accept" => "application/json" })

      raise Error, "Rekor index search failed: #{resp.code} #{resp.body}" unless resp.code == "200"

      uuids = JSON.parse(resp.body)
      raise Error, "No Rekor entries found for hash sha256:#{sha256_hex}" if uuids.empty?

      # Fetch each entry and find the one with our certificate
      uuids.each do |uuid|
        entries_url = URI.join(client_url, "log/entries/#{uuid}")
        entry_resp = session.get2(entries_url.path, { "Accept" => "application/json" })
        next unless entry_resp.code == "200"

        entry_data = JSON.parse(entry_resp.body)
        entry_data.each do |_uuid, result|
          body = JSON.parse(Internal::Util.base64_decode(result.fetch("body")))
          next unless body["kind"] == "hashedrekord"

          cert_pem = Internal::Util.base64_decode(body.dig("spec", "signature", "publicKey", "content"))
          entry_cert = OpenSSL::X509::Certificate.new(cert_pem)

          if entry_cert.to_der == expected_cert.to_der
            return Rekor::Entries.decode_transparency_log_entry(entry_data)
          end
        end
      end

      raise Error, "No Rekor entry found with matching certificate"
    end
  end
end
