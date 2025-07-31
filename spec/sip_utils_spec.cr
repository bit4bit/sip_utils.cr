require "./spec_helper"

describe SIPUtils::Network::SIP do
  it "parse SIP Response" do
    response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"))
    response.status_code.should eq 200
    response.headers["Via"].should eq("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj")
  end

  it "parse SIP Request" do
    request = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).parse(IO::Memory.new("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"))

    request.method.should eq "INVITE"
    request.uri.should eq "sip:bob@example.com"
    request.version.should eq "SIP/2.0"
    request.headers["To"].should eq("Bob <sip:bob@example.com>;tag=67890")
  end

  it "valid?" do
    SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).valid?(IO::Memory.new("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")).should be_true
    SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).valid?(IO::Memory.new("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")).should be_true

    SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).valid?(IO::Memory.new("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")).should be_false
    SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).valid?(IO::Memory.new("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")).should be_false
  end
end
