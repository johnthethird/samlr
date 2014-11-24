require "time"
require "uuidtools"
require "openssl"
require "cgi"
require "zlib"

require "samlr/tools/timestamp"
require "samlr/tools/certificate_builder"
require "samlr/tools/request_builder"
require "samlr/tools/response_builder"
require "samlr/tools/metadata_builder"
require "samlr/tools/logout_request_builder"

module Samlr
  module Tools

    if RUBY_ENGINE == 'jruby'
      Dir.glob("#{File.join(File.dirname(__FILE__), "..", "..", "ext")}/*.jar").each { |f| $CLASSPATH << f }
      import 'org.apache.xml.security.c14n.Canonicalizer'
      # This has to be done to Init the logging subsystem, even though we arent using it
      org.apache.xml.security.Init.init
    end

    SHA_MAP = {
      1    => OpenSSL::Digest::SHA1,
      256  => OpenSSL::Digest::SHA256,
      384  => OpenSSL::Digest::SHA384,
      512  => OpenSSL::Digest::SHA512
    }

    # Convert algorithm attribute value to Ruby implementation
    def self.algorithm(value)
      if value =~ /sha(\d+)$/
        implementation = SHA_MAP[$1.to_i]
      end

      implementation || OpenSSL::Digest::SHA1
    end

    # Accepts a document and optionally :path => xpath, :c14n_mode => c14n_mode
    def self.canonicalize(xml, options = {})
      options  = { :c14n_mode => C14N }.merge(options)
      if [Nokogiri::XML::Element, Nokogiri::XML::Document].include?(xml.class)
        document = xml
      else
        document = Nokogiri::XML(xml, nil, "UTF-8") { |c| c.strict.noblanks }
      end

      if path = options[:path]
        node = document.at(path, NS_MAP)
      else
        node = document
      end

      if RUBY_ENGINE == 'jruby'
        # without this next line you get these when running the tests:
        # Java::OrgXmlSax::SAXParseException: The prefix "saml" for element "saml:Assertion" is not bound.
        node.namespaces.each_pair {|key, value| node[key] = value }
        c = Canonicalizer.getInstance(Canonicalizer::ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
        String.from_java_bytes(c.canonicalize(node.to_xml(:encoding => "UTF-8").to_java_bytes))
      else
        node.canonicalize(options[:c14n_mode], options[:namespaces])
      end

    end

    # Generate an xs:NCName conforming UUID
    def self.uuid
      "samlr-#{UUIDTools::UUID.timestamp_create}"
    end

    # Deflates, Base64 encodes and CGI escapes a string
    def self.encode(string)
      deflated = Zlib::Deflate.deflate(string, 9)[2..-5]
      encoded  = Base64.encode64(deflated)
      escaped  = CGI.escape(encoded)
      escaped
    end

    # CGI unescapes, Base64 decodes and inflates a string
    def self.decode(string)
      unescaped = CGI.unescape(string)
      decoded   = Base64.decode64(unescaped)
      inflater  = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      inflated  = inflater.inflate(decoded)

      inflater.finish
      inflater.close

      inflated
    end

    def self.validate!(options = {})
      validate(options.merge(:bang => true))
    end

    # Validate a SAML request or response against an XSD. Supply either :path or :document in the options and
    # a :schema (defaults to SAML validation)
    def self.validate(options = {})
      document = options[:document] || File.read(options[:path])
      schema   = options.fetch(:schema, SAML_SCHEMA)
      bang     = options.fetch(:bang, false)

      if document.is_a?(Nokogiri::XML::Document)
        xml = document
      else
        xml = Nokogiri::XML(document, nil, "UTF-8") { |c| c.strict }
      end

      # All bundled schemas are using relative schemaLocation. This means we'll have to
      # change working directory to find them during validation.
      Dir.chdir(Samlr.schema_location) do
        if schema.is_a?(Nokogiri::XML::Schema)
          xsd = schema
        else
          xsd = Nokogiri::XML::Schema(File.read(schema))
        end

        result = xsd.validate(xml)

        if bang && result.length != 0
          raise Samlr::FormatError.new("Schema validation failed", "XSD validation errors: #{result.join(", ")}")
        else
          result.length == 0
        end
      end
    end
  end
end
