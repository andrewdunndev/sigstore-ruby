# frozen_string_literal: true

require "test_helper"
require "sigstore/gitsign"

class Sigstore::GitsignTest < Test::Unit::TestCase
  # A minimal self-signed certificate for testing parse_cms_signature.
  # In real usage this would be a Fulcio-issued short-lived cert.
  def setup
    @key = OpenSSL::PKey::EC.generate("prime256v1")
    @cert = OpenSSL::X509::Certificate.new
    @cert.version = 2
    @cert.serial = 1
    @cert.subject = OpenSSL::X509::Name.parse("/CN=test")
    @cert.issuer = @cert.subject
    @cert.public_key = @key
    @cert.not_before = Time.now - 60
    @cert.not_after = Time.now + 300

    # Add Fulcio OIDC issuer extension to make it look like a Fulcio cert
    ef = OpenSSL::X509::ExtensionFactory.new
    @cert.add_extension(ef.create_extension("subjectAltName", "email:test@example.com", false))

    @cert.sign(@key, "SHA256")

    @payload = "tree abc123\nauthor Test <test@example.com>\n\nTest commit\n"
  end

  def make_pkcs7_signature(payload)
    p7 = OpenSSL::PKCS7.sign(@cert, @key, payload, [@cert], OpenSSL::PKCS7::DETACHED | OpenSSL::PKCS7::BINARY)
    p7.to_pem
  end

  def test_parse_cms_signature_extracts_certificate
    sig_pem = make_pkcs7_signature(@payload)
    result = Sigstore::Gitsign.parse_cms_signature(sig_pem)

    assert_kind_of OpenSSL::X509::Certificate, result[:certificate]
    assert_equal @cert.subject.to_s, result[:certificate].subject.to_s
    assert_kind_of String, result[:signature]
    assert result[:all_certificates].size >= 1
  end

  def test_parse_cms_signature_handles_gitsign_header
    sig_pem = make_pkcs7_signature(@payload)
    # gitsign uses custom PEM headers
    gitsign_pem = sig_pem
      .sub("-----BEGIN PKCS7-----", "-----BEGIN SIGNED MESSAGE-----")
      .sub("-----END PKCS7-----", "-----END SIGNED MESSAGE-----")

    result = Sigstore::Gitsign.parse_cms_signature(gitsign_pem)
    assert_kind_of OpenSSL::X509::Certificate, result[:certificate]
  end

  def test_fulcio_issued_without_oidc_extension
    # Our test cert does NOT have the Fulcio OIDC issuer extension
    refute Sigstore::Gitsign.fulcio_issued?(@cert)
  end

  def test_fulcio_issued_with_oidc_extension
    # Add the Fulcio OIDC issuer v1 extension
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 2
    cert.subject = OpenSSL::X509::Name.parse("/CN=fulcio-test")
    cert.issuer = cert.subject
    cert.public_key = @key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 300

    # OID 1.3.6.1.4.1.57264.1.1 is the Fulcio OIDC Issuer extension
    ext = OpenSSL::X509::Extension.new("1.3.6.1.4.1.57264.1.1", "https://accounts.google.com")
    cert.add_extension(ext)
    cert.sign(@key, "SHA256")

    assert Sigstore::Gitsign.fulcio_issued?(cert)
  end

  def test_verify_commit_rejects_non_fulcio_cert
    sig_pem = make_pkcs7_signature(@payload)

    trust_root = Sigstore::TrustedRoot.production(offline: true)
    policy = Sigstore::Policy::Identity.new(identity: "test@example.com", issuer: "https://accounts.google.com")

    result = Sigstore::Gitsign.verify_commit(
      signature_pem: sig_pem,
      signed_payload: @payload,
      trust_root: trust_root,
      policy: policy
    )

    refute result.verified?
    assert_match(/not Fulcio-issued/, result.reason)
  end
end
