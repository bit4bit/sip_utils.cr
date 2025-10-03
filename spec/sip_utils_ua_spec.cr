require "./spec_helper"

class StubTagger < SIPUtils::Network::UA::Tagger
  def initialize(@branch : String, @tag : String, @call_id : String, @cnonce : String)
  end

  def tag
    @tag
  end

  def branch
    @branch
  end

  def call_id
    @call_id
  end

  def cnonce
    @cnonce
  end
end

describe SIPUtils::Network::UA do
  it "send REGISTER, receive 401, send REGISITER with www-authentication" do
    tagger = StubTagger.new(branch: "z9hG4bK1234567890", tag: "1234567890", call_id: "1234567890", cnonce: "1234567890")
    ua = SIPUtils::Network::UA.new(user: "user", realm: "realm", via_address: "127.0.0.1:5060", tagger: tagger)

    req = ua.register
    SIPUtils::Network.encode(req).should eq("REGISTER sip:user@realm SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1234567890\r\nFrom: <sip:user@realm>;tag=1234567890\r\nTo: <sip:user@realm>\r\nCall-ID: 1234567890\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 1\r\nContact: <sip:user@127.0.0.1:5060>\r\nExpires: 3600\r\nAllow: INVITE,ACK,BYE,CANCEL,REGISTER\r\nUser-Agent: SIPUtils\r\n\r\n")
    response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new("SIP/2.0 401 Unauthorized\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1234567890\r\nFrom: <sip:user@realm>;tag=1234567890\r\nTo: <sip:user@realm>;tag=1234567890\r\nCall-ID: 1234567890\r\nCSeq: 1 REGISTER\r\nMax-Forwards: 1\r\nContact: <sip:user@127.0.0.1:5060>\r\nExpires: 3600\r\nAllow: INVITE,ACK,BYE,CANCEL,REGISTER\r\nUser-Agent: SipUtils\r\nWWW-Authenticate: Digest realm=\"realm\", nonce=\"abcdef1234567890\", algorithm=MD5, qop=\"auth\"\r\n\r\n"))

    req = ua.www_authenticate(req, response, "password")
    req.headers["Authorization"].should eq(%q[Digest username="user",realm="realm",nonce="abcdef1234567890",uri="sip:realm",response="ac8ed6e033561189b6c55fc601be3ead",algorithm=MD5,qop=auth,nc=00000001,cnonce="1234567890"])
  end

  it "answer INVITE" do
    tagger = StubTagger.new(branch: "z9hG4bK1234567890", tag: "1234567890", call_id: "1234567890", cnonce: "1234567890")
    ua = SIPUtils::Network::UA.new(user: "user", realm: "realm", via_address: "127.0.0.1:5060", tagger: tagger)

    req_invite = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).parse(IO::Memory.new("INVITE sip:user@realm SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1234567890\r\nFrom: <sip:user@realm>;tag=1234567890\r\nTo: <sip:user@realm>\r\nCall-ID: 1234567890\r\nCSeq: 0 INVITE\r\nMax-Forwards: 1\r\nContact: <sip:user@127.0.0.1:5060>\r\nAllow: INVITE,ACK,BYE,CANCEL,REGISTER\r\nUser-Agent: SIPUtils\r\n\r\n"))
    resp = ua.answer_invite(request: req_invite, media_address: "127.0.0.1", media_port: 49170, session_id: "0")
    sdp_body = "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=SIPUtils\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
    content_length = sdp_body.bytesize
    SIPUtils::Network.encode(resp).should eq(
      "SIP/2.0 200 OK\r\n" +
      "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK1234567890\r\n" +
      "From: <sip:user@realm>;tag=1234567890\r\n" +
      "To: <sip:user@realm>;tag=1234567890\r\n" +
      "Call-ID: 1234567890\r\n" +
      "CSeq: 0 INVITE\r\n" +
      "Contact: <sip:user@127.0.0.1:5060>\r\n" +
      "Content-Type: application/sdp\r\n" +
      "Content-Length: #{content_length}\r\n" +
      "\r\n" +
      sdp_body
    )
  end
end
