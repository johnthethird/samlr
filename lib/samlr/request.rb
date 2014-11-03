require "cgi"

module Samlr
  class Request
    attr_reader :options

    def initialize(options = {})
      @options = options
    end

    # The encoded SAML request
    def param
      @param ||= Samlr::Tools.encode(body)
    end

    # The XML payload body
    def body
      @body ||= Samlr::Tools::RequestBuilder.build(options)
    end

    # Utility method to get the full redirect destination, Request#url("https://idp.example.com/saml", { :RelayState => "https://sp.example.com/saml" })
    def url(root, params = {})
      buffer = root.dup
      buffer << (buffer.include?("?") ? "&" : "?")

      signable = "SAMLRequest=#{param}"
      signable << "&RelayState=#{CGI.escape(params.delete(:RelayState))}" if params[:RelayState]

      if options[:sign_requests]
        signable << "&SigAlg=#{CGI.escape('http://www.w3.org/2000/09/xmldsig#rsa-sha1')}"
        signature = compute_signature(signable)
        signable << "&Signature=#{signature}"
      end

      buffer << signable

      params.each_pair do |key, value|
        buffer << "&#{key}=#{CGI.escape(value.to_s)}"
      end

      buffer
    end

    private
    def compute_signature(signable)
      key_pair  = OpenSSL::PKey::RSA.new(options[:saml_signing_key])
      sig = key_pair.sign(OpenSSL::Digest::SHA1.new, signable)
      CGI.escape(Base64.encode64(sig).delete("\n"))
    end
  end
end
