require "./spec_helper"

describe SIPUtils::Network::SIP do
  it "parse SIP Response" do
    response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"))
    response.status_code.should eq 200
    response.headers["Via"].should eq("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj")
  end

  it "parse SIP response application/sdp" do
    sdp_body = "v=0\no=alice 2890844526 2890844526 IN IP4 host.atlanta.com\ns=-\nc=IN IP4 host.atlanta.com\nt=0 0\nm=audio 49170 RTP/AVP 0\na=rtpmap:0 PCMU/8000"
    content_type = "application/sdp"
    sip_message = "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Type: #{content_type}\r\nContent-Length: #{sdp_body.size}\r\n\r\n#{sdp_body}"
    response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new(sip_message))

    response.headers["Content-Type"].should eq(content_type)
    response.body.should eq(sdp_body)

    sdp = SIPUtils::Network::SIP(SIPUtils::Network::SIP::SDP).parse(IO::Memory.new(sdp_body))
    sdp.version.should eq(0)
    sdp.origin.should eq("alice 2890844526 2890844526 IN IP4 host.atlanta.com")
    sdp.session_name.should eq("-")
    sdp.connection.should eq("IN IP4 host.atlanta.com")
    sdp.time.should eq("0 0")
    sdp.media.should eq("audio 49170 RTP/AVP 0")
    sdp.attributes.should eq(["rtpmap:0 PCMU/8000"])
  end

  it "parse SIP Request" do
    request = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).parse(IO::Memory.new("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"))

    request.method.should eq "INVITE"
    request.uri.should eq "sip:bob@example.com"
    request.version.should eq "SIP/2.0"
    request.headers["To"].should eq("Bob <sip:bob@example.com>;tag=67890")
  end

  it "encode SIP Request" do
    request = SIPUtils::Network::SIP::Request.new("INVITE", "sip:bob@example.com", "SIP/2.0")
    request.headers["Via"] = "SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj"
    request.headers["From"] = "Alice <sip:alice@example.com>;tag=12345"
    request.headers["To"] = "Bob <sip:bob@example.com>;tag=67890"
    request.headers["Call-ID"] = "1234567890@example.com"
    request.headers["CSeq"] = "1 INVITE"
    request.headers["Content-Length"] = "0"
    SIPUtils::Network.encode(request).should eq("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
  end

  it "encode SIP Response" do
    response = SIPUtils::Network::SIP::Response.new(SIPUtils::Network::SIP::Status::Ok, 200, "SIP/2.0")
    response.headers["Via"] = "SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj"
    response.headers["From"] = "Alice <sip:alice@example.com>;tag=12345"
    response.headers["To"] = "Bob <sip:bob@example.com>;tag=67890"
    response.headers["Call-ID"] = "1234567890@example.com"
    response.headers["CSeq"] = "1 INVITE"
    response.headers["Content-Length"] = "0"
    SIPUtils::Network.encode(response).should eq("SIP/2.0 200 Ok\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
  end

  it "valid?" do
    SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).valid?(IO::Memory.new("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")).should be_true
    SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).valid?(IO::Memory.new("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")).should be_true

    SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).valid?(IO::Memory.new("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")).should be_false
    SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).valid?(IO::Memory.new("INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK776asdhj\r\nFrom: Alice <sip:alice@example.com>;tag=12345\r\nTo: Bob <sip:bob@example.com>;tag=67890\r\nCall-ID: 1234567890@example.com\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")).should be_false
  end
end
