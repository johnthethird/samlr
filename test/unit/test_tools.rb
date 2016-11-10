require File.expand_path("test/test_helper")
require "openssl"

describe Samlr::Tools do

  describe "::canonicalize" do
    before do
      @fixture = fixed_saml_response.document.to_xml
    end

    it "should namespace the SignedInfo element" do
      path = "/samlp:Response/ds:Signature/ds:SignedInfo"
      assert_match '<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">', Samlr::Tools.canonicalize(@fixture, { :path => path })
    end
  end

  describe "::jruby c14n Okta" do
    before do
      @fixture = File.read(File.join(FIXTURE_PATH, "sample_response_okta.xml"), :encoding => 'UTF-8')
      @properly_canoned = File.read(File.join(FIXTURE_PATH, "sample_response_okta_c14n_mri.xml"), :encoding => 'UTF-8')
    end

    it "should c14n Response" do
      xml = Nokogiri::XML(@fixture, nil, "UTF-8") { |c| c.strict.noblanks }
      node = xml.at("//*[@ID='id26775890404714381981713714']", Samlr::NS_MAP)
      signature = node.at("/samlp:Response/ds:Signature", Samlr::NS_MAP)
      signature.remove
      assert_equal @properly_canoned, Samlr::Tools.canonicalize(xml, :path => "//*[@ID='id26775890404714381981713714']", :namespaces => ['xs'])
    end

    it "should c14n SignedInfo" do
      xml = Nokogiri::XML(@fixture, nil, "UTF-8") { |c| c.strict.noblanks }
      #node = xml.at("//*[@ID='id26775890404714381981713714']", Samlr::NS_MAP)
      #signature = node.at("/samlp:Response/ds:Signature", Samlr::NS_MAP)

      good = '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#id26775890404714381981713714"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xs"></ec:InclusiveNamespaces></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>iOf7+1VJ1X0EeEulKXz0lvsFU6s=</ds:DigestValue></ds:Reference></ds:SignedInfo>'
      assert_equal good, Samlr::Tools.canonicalize(xml, :path => "/samlp:Response/ds:Signature/ds:SignedInfo")
    end

    it "should validate the fixture" do
      doc = Samlr::Response.new(@fixture, {:skip_fingerprint => true})
      Time.stub(:now, Time.new('2014','11','30','03','54','30', '+00:00')) do
        doc.verify!
      end
    end
  end

  describe "::jruby c14n adfs" do
    before do
      @fixture = File.read(File.join(FIXTURE_PATH, "sample_response_adfs.xml"), :encoding => 'UTF-8')
      @properly_canoned = File.read(File.join(FIXTURE_PATH, "sample_response_adfs_c14n_mri.xml"), :encoding => 'UTF-8')
    end

    it "should c14n Response" do
      xml = Nokogiri::XML(@fixture, nil, "UTF-8") { |c| c.strict.noblanks }
      node = xml.at("//*[@ID='_7b459394-07fb-42ec-9b98-ce0cbd048895']", Samlr::NS_MAP)
      signature = node.at("/samlp:Response/ds:Signature", Samlr::NS_MAP)
      signature.remove
      assert_equal @properly_canoned, Samlr::Tools.canonicalize(xml, :path => "//*[@ID='_7b459394-07fb-42ec-9b98-ce0cbd048895']", :namespaces => ['xs'])
    end

    it "should c14n SignedInfo" do
      xml = Nokogiri::XML(@fixture, nil, "UTF-8") { |c| c.strict.noblanks }
      #node = xml.at("//*[@ID='_7b459394-07fb-42ec-9b98-ce0cbd048895']", Samlr::NS_MAP)
      #signature = node.at("/samlp:Response/ds:Signature", Samlr::NS_MAP)

      good = '<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"></ds:SignatureMethod><ds:Reference URI="#_7b459394-07fb-42ec-9b98-ce0cbd048895"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"></ds:DigestMethod><ds:DigestValue>shZBebTIT6qcHIhgcnDGiv5ETV4=</ds:DigestValue></ds:Reference></ds:SignedInfo>'
      assert_equal good, Samlr::Tools.canonicalize(xml, :path => "/samlp:Response/ds:Signature/ds:SignedInfo")
    end

    it "should validate the fixture" do
      doc = Samlr::Response.new(@fixture, {:skip_fingerprint => true})
      Time.stub(:now, Time.new('2014','11','30','03','40','02', '+00:00')) do
        doc.verify!
      end
    end
  end

  describe "::uuid" do
    it "generates a valid xs:ID" do
      assert Samlr::Tools.uuid !~ /^\d/
    end
  end

  describe "::algorithm" do
    [ 1, 384, 512 ].each do |i|
      describe "when fed SHA#{i}" do
        subject { "#sha#{i}" }

        it "should return the corresponding implementation" do
          assert_equal eval("OpenSSL::Digest::SHA#{i}"), Samlr::Tools.algorithm(subject)
        end
      end
    end

    describe "when not specified" do
      subject { nil }

      it "should default to SHA1" do
        assert_equal OpenSSL::Digest::SHA1, Samlr::Tools.algorithm(subject)
      end
    end

    describe "when not known" do
      subject { "sha73" }

      it "should default to SHA1" do
        assert_equal OpenSSL::Digest::SHA1, Samlr::Tools.algorithm(subject)
      end
    end
  end

  describe "::encode and ::decode" do
    it "compresses a string in a reversible fashion" do
      assert_equal "12345678", Samlr::Tools.decode(Samlr::Tools.encode("12345678"))
    end
  end

  describe "::validate" do
    subject { saml_response_document(:certificate => TEST_CERTIFICATE) }

    it "returns true for valid documents" do
      assert Samlr::Tools.validate(:document => subject)
    end

    it "returns false for invalid documents" do
      mangled = subject.gsub("Assertion", "AyCaramba")
      refute Samlr::Tools.validate(:document => mangled)
    end

    it "does not change the working directory" do
      path = Dir.pwd
      assert Samlr::Tools.validate(:document => subject)
      assert_equal path, Dir.pwd
    end
  end

  describe "::validate!" do
    subject { saml_response_document(:certificate => TEST_CERTIFICATE) }

    it "returns true for valid documents" do
      assert Samlr::Tools.validate!(:document => subject)
    end

    it "raises for invalid documents" do
      mangled = subject.gsub("Assertion", "AyCaramba")

      begin
        Samlr::Tools.validate!(:document => mangled)
        flunk "Errors expected"
      rescue Samlr::FormatError => e
        assert_equal "Schema validation failed", e.message
      end
    end

    it "does not change the working directory" do
      path = Dir.pwd
      assert Samlr::Tools.validate!(:document => subject)
      assert_equal path, Dir.pwd
    end
  end
end
