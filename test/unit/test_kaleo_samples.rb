require File.expand_path("test/test_helper")
require 'pry'
require 'timecop'

describe Samlr do

  describe "test all examples" do


    it "verifies" do
      skip

      Samlr.validation_mode = :log

      Dir.glob("/Users/john/Downloads/sso_logins/*.xml") do |fname|
        begin
          puts "#{fname}..."
          xml = File.read(fname)
          xml =~ /X509Certificate>([^<]*)/
          pem = ["-----BEGIN CERTIFICATE-----", $1, "-----END CERTIFICATE-----"].join("\n").gsub(/\n+/,"\n")
          fingerprint = Samlr::FingerprintSHA1.x509(OpenSSL::X509::Certificate.new(pem))

          xml =~ /IssueInstant="([^"]*)"/
          ts = $1

          Timecop.freeze(ts) do
            doc = Samlr::Response.new(xml, :fingerprint => fingerprint)
            doc.verify!
          end
        rescue StandardError => e
          #binding.pry
          puts e
        end
      end
    end
  end
end
