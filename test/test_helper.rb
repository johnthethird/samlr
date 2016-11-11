require "bundler/setup"
require "minitest/autorun"
require 'pry'
require "time"
require "base64"
require "tmpdir"

require "samlr"
require "samlr/tools/response_builder"
require "samlr/tools/certificate_builder"

FIXTURE_PATH     = File.join(File.dirname(__FILE__), "fixtures")
TEST_CERTIFICATE = Samlr::Tools::CertificateBuilder.load(FIXTURE_PATH, "default_samlr")

def saml_response_document(options = {})
  # Test defaults
  options = {
    :destination     => "https://example.org/saml/endpoint",
    :in_response_to  => Samlr::Tools.uuid,
    :name_id         => "someone@example.org",
    :audience        => "example.org",
    :not_on_or_after => Samlr::Tools::Timestamp.stamp(Time.now + 60),
    :not_before      => Samlr::Tools::Timestamp.stamp(Time.now - 60),
    :response_id     => Samlr::Tools.uuid
  }.merge(options)

  Samlr::Tools::ResponseBuilder.build(options)
end

def saml_response(options = {})
  fingerprint   = options[:fingerprint]
  fingerprint ||= options[:certificate] ? Samlr::FingerprintSHA256.x509(options[:certificate].x509) : nil

  Samlr::Response.new(saml_response_document(options), :fingerprint => fingerprint)
end

# A response that never changes. Useful for digest checks etc.
def fixed_saml_response(options = {})
  options = {
    :certificate     => TEST_CERTIFICATE,
    :issue_instant   => Samlr::Tools::Timestamp.stamp(Time.at(1344379365)),
    :response_id     => "samlr123",
    :assertion_id    => "samlr456",
    :in_response_to  => "samlr789",
    :attributes      => { "tags" => "mean horse", "things" => [ "one", "two", "three" ] },
    :not_on_or_after => Samlr::Tools::Timestamp.stamp(Time.at(1344379365 + 60)),
    :not_before      => Samlr::Tools::Timestamp.stamp(Time.at(1344379365 - 60))
  }.merge(options)

  if RUBY_ENGINE == 'jruby'
    # For some reason, JRuby Nokogiri does not output the namespaces when building the
    # response with arrays of attrs, which causes it to fail in parsing the test response.
    # <saml:Attribute Name="things">
    #     <saml:AttributeValue type="xs:string">one</saml:AttributeValue>
    #     <saml:AttributeValue type="xs:string">two</saml:AttributeValue>
    #     <saml:AttributeValue type="xs:string">three</saml:AttributeValue>
    # </saml:Attribute>
    options[:attributes] = { "tags" => "mean horse"}
  end

  saml_response(options)
end
