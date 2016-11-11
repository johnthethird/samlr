module Samlr
  class Assertion
    DEFAULT_LOCATION = "/samlp:Response/saml:Assertion"
    attr_reader :document, :options

    def initialize(document, options)
      @document = document
      @options  = options
    end

    def verify!
      verify_signature!
      verify_conditions! unless skip_conditions?

      true
    end

    def location
      @location ||= if !signature.missing?
        verify_signature!
        "//saml:Assertion[@ID='#{signature.references.first.uri}']"
      else
        DEFAULT_LOCATION
      end
    end

    def signature
      @signature ||= Samlr::Signature.new(document, DEFAULT_LOCATION, options)
    end

    def attributes
      @attributes ||= {}.tap do |attrs|
        assertion.xpath("./saml:AttributeStatement/saml:Attribute", NS_MAP).each do |statement|
          name   = statement["Name"]
          values = statement.xpath("./saml:AttributeValue", NS_MAP)

          if values.size == 0
            next
          elsif values.size == 1
            value = values.first.text
          else
            value = values.map { |v| v.text }
          end

          attrs[name] = attrs[name.to_sym] = value
        end
      end
    end

    def name_id
      if !name_id_node
        raise Samlr::FormatError.new("Invalid SAML response: name_id missing")
      else
        @name_id ||= name_id_node.text
      end
    end

    def name_id_options
      @name_id_options ||= Hash[name_id_node.attributes.map{|k,v| [k, v.value]}]
    end

    def conditions
      @conditions ||= Condition.new(assertion.at("./saml:Conditions", NS_MAP), options)
    end

    private

    def name_id_node
      @name_id_node ||= assertion.at("./saml:Subject/saml:NameID", NS_MAP)
    end

    def assertion
      @assertion ||= document.at(location, NS_MAP)
    end

    def verify_signature!
      verify_assertion!
      signature.verify! unless signature.missing?

      true
    end

    def skip_conditions?
      !!options[:skip_conditions]
    end

    def verify_conditions!
      conditions.verify!
    end

    def verify_assertion!
      assertion_count = document.xpath("//saml:Assertion", NS_MAP).size

      if assertion_count == 0
        raise Samlr::FormatError.new("Invalid SAML response: assertion missing")
      elsif assertion_count != 1
        raise Samlr::FormatError.new("Invalid SAML response: unexpected number of assertions")
      end

      true
    end
  end
end
