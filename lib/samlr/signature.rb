require "openssl"
require "base64"
require "samlr/certificate"
require "samlr/reference"

module Samlr
  # A SAML specific implementation http://en.wikipedia.org/wiki/XML_Signature
  class Signature

    if RUBY_ENGINE == 'jruby'
     $CLASSPATH << File.join(File.dirname(__FILE__), "..", "..", "ext")
     import "Validator" unless defined?("Java::Default::Validator")
    end

    attr_reader :original, :document, :prefix, :options, :signature, :fingerprints

    # Is initialized with the source document and a path to the element embedding the signature
    def initialize(original, prefix, options)
      # Signature validations require document alterations
      @original = original
      @document = original.dup
      @prefix   = prefix
      @options  = options

      if @signature = document.at("#{prefix}/ds:Signature", NS_MAP)
        @signature.remove # enveloped signatures only
      end

      # Add ability to have an array of fingerprints and check them all
      all_fingerprints = [options[:fingerprint], options[:fingerprints]].flatten.compact.uniq
      @fingerprints = if all_fingerprints.size > 0
        all_fingerprints.map{|f| Fingerprint.from_string(f)}.compact.uniq
      elsif options[:certificate]
        [Certificate.new(options[:certificate]).fingerprint]
      end
    end

    def present?
      !missing?
    end

    def missing?
      signature.nil? || certificate.nil?
    end

    def verify!
      raise SignatureError.new("No signature at #{prefix}/ds:Signature") unless present?

      verify_fingerprint! unless options[:skip_fingerprint]

      # HACK since Nokogiri doesnt support C14N under JRuby.
      # So we use the Validate.java class to do the validation using JSR-105 API in xmlsec-1.5.3.jar
      # We must use the raw response data we get *before* nokogiri munges it, or else the Java validator doesnt always work.
      # Probably a C14N issue.
      if RUBY_ENGINE == 'jruby' && options.fetch(:java_signature_validator, true)
        Samlr.logger.info("[SAMLR] Using Java Signature Validation") if options[:debug]
        begin
          # #validate expects pem to be a blank string not nil, if empty
          cert = options.fetch(:certificate, "")
          pem = cert.respond_to?(:to_pem) ? cert.to_pem : cert
          unless Java::Default::Validator.validate(@original.to_s, pem)
            raise SignatureError.new("Signature validation error (java).")
          end
        rescue Exception => e
          raise SignatureError.new("Signature validation error (java): #{e.message}")
        end
      else
        verify_digests!
        verify_signature!
      end

      true
    end

    def references
      @references ||= [].tap do |refs|
        original.xpath("#{prefix}/ds:Signature/ds:SignedInfo/ds:Reference[@URI]", NS_MAP).each do |ref|
          refs << Samlr::Reference.new(ref)
        end
      end
    end

    private

    def x509
      @x509 ||= certificate!.x509
    end

    # Establishes trust that the remote party is who you think
    # Since we have multiple fingerprints, only one needs to succeed the rest will fail.
    def verify_fingerprint!
      verified = false
      fingerprints.each do |f|
        (verified = f.verify!(certificate!)) rescue Samlr::FingerprintError
      end
      raise Samlr::FingerprintError.new("Fingerprint mismatch") unless verified
    end

    # Tests that the document content has not been edited
    def verify_digests!
      references.each do |reference|
        node    = referenced_node(reference.uri)
        canoned = Samlr::Tools.canonicalize(node, :path => "//*[@ID='#{reference.uri}']", :namespaces => reference.namespaces)
        digest  = reference.digest_method.digest(canoned)

        if digest != reference.decoded_digest_value
          raise SignatureError.new("Reference validation error: Digest mismatch for #{reference.uri}")
        end
      end
    end

    # Tests correctness of the signature (and hence digests)
    def verify_signature!
      canoned = Samlr::Tools.canonicalize(original, :path => "#{prefix}/ds:Signature/ds:SignedInfo")

      unless x509.public_key.verify(signature_method.new, decoded_signature_value, canoned)
        raise SignatureError.new("Signature validation error: Possible canonicalization mismatch", "This canonicalizer returns #{canoned}")
      end
    end

    # Looks up node by id, checks that there's only a single node with a given id
    def referenced_node(id)
      nodes = document.xpath("//*[@ID='#{id}']")

      if nodes.size != 1
        raise SignatureError.new("Reference validation error: Invalid element references", "Expected 1 element with id #{id}, found #{nodes.size}")
      end

      nodes.first
    end

    def signature_method
      @signature_method ||= Samlr::Tools.algorithm(signature.at("./ds:SignedInfo/ds:SignatureMethod/@Algorithm", NS_MAP).try(:value))
    end

    def signature_value
      @signature_value ||= signature.at("./ds:SignatureValue", NS_MAP).text
    end

    def decoded_signature_value
      @decoded_signature_value = Base64.decode64(signature_value)
    end

    def certificate
      @certificate ||= begin
        if node = certificate_node
          Certificate.new(Base64.decode64(node.text))
        elsif cert = options[:certificate]
          Certificate.new(cert)
        else
          nil
        end
      end
    end

    def certificate!
      certificate || raise(SignatureError.new("No X509Certificate element in response signature. Cannot validate signature."))
    end

    def certificate_node
      signature.at("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", NS_MAP)
    end

  end
end
