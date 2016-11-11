require File.expand_path("test/test_helper")

describe Samlr::Response do

  subject { fixed_saml_response }

  describe "#name_id" do
    it "delegates to the assertion" do
      subject.assertion.stub(:name_id, "george") do
        assert_equal("george", subject.name_id)
      end
    end
  end

  describe "#attributes" do
    it "delegates to the assertion" do
      subject.assertion.stub(:attributes, { :name => "george" }) do
        assert_equal({ :name => "george" }, subject.attributes)
      end
    end
  end

  describe "#location" do
    it "should return proper assertion location" do
      assert_equal "//saml:Assertion[@ID='samlr456']", subject.assertion.location
    end
  end

  describe "XSW attack" do
    it "should not validate if SAML response is hacked" do
      skip if RUBY_ENGINE == 'jruby'

      document = saml_response_document(:certificate => TEST_CERTIFICATE)

      modified_document = Nokogiri::XML(document)

      original_assertion = modified_document.xpath("/samlp:Response/saml:Assertion", Samlr::NS_MAP).first

      response_signature = modified_document.xpath("/samlp:Response/ds:Signature", Samlr::NS_MAP).first

      extensions = Nokogiri::XML::Node.new "Extensions", modified_document
      extensions << original_assertion.to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML)
      response_signature.add_next_sibling(extensions)
      response_signature.remove()

      modified_document.xpath("/samlp:Response/samlp:Extensions/saml:Assertion/ds:Signature", Samlr::NS_MAP).remove
      modified_document.xpath("/samlp:Response/saml:Assertion/saml:Subject/saml:NameID", Samlr::NS_MAP).first.content="evil@example.org"
      modified_document.xpath("/samlp:Response/saml:Assertion", Samlr::NS_MAP).first["ID"] = "evil_id"

      response = Samlr::Response.new(modified_document.to_xml(:save_with => Nokogiri::XML::Node::SaveOptions::AS_XML), {:certificate => TEST_CERTIFICATE.x509})
      assert_raises(Samlr::FormatError) { response.verify! }
    end
  end

  describe "::parse" do
    before { @document = saml_response_document(:certificate => TEST_CERTIFICATE) }

    describe "when given a raw XML response" do
      it "constructs and XML document" do
        assert_equal Nokogiri::XML::Document, Samlr::Response.parse(@document).class
      end
    end

    describe "when given a Base64 encoded response" do
      subject { Base64.encode64(@document) }

      it "constructs and XML document" do
        assert_equal Nokogiri::XML::Document, Samlr::Response.parse(subject).class
      end
    end

    describe "when given an invalid string" do
      it "fails" do
        assert_raises(Samlr::FormatError) { Samlr::Response.parse("hello") }
      end
    end

    describe "when given a malformed XML response" do
      subject { saml_response_document(:certificate => TEST_CERTIFICATE).gsub("Assertion", "AyCaramba") }
      after   { Samlr.validation_mode = :reject }

      describe "and Samlr.validation_mode == :log" do
        before { Samlr.validation_mode = :log }
        it "does not raise" do
          assert Samlr::Response.parse(subject)
        end
      end

      describe "and Samlr.validation_mode != :log" do
        it "raises" do
          # Dont do this test on JRuby because we skip the validations anyway
          skip if RUBY_ENGINE == 'jruby'
          assert_raises(Samlr::FormatError) { Samlr::Response.parse(subject) }
        end
      end

    end
  end
end
