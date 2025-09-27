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

  it "parse RTP packet and extract payload" do
    # Create a simple RTP packet with PCMU payload
    # Version=2, No padding, No extension, CC=0, No marker, PT=0 (PCMU), Seq=12345, TS=67890, SSRC=0x12345678
    rtp_data = Bytes[
      0x80, 0x00,             # V=2, P=0, X=0, CC=0, M=0, PT=0
      0x30, 0x39,             # Sequence number: 12345
      0x00, 0x01, 0x09, 0x32, # Timestamp: 67890
      0x12, 0x34, 0x56, 0x78, # SSRC: 0x12345678
      0xDE, 0xAD, 0xBE, 0xEF  # Payload: 4 bytes
    ]

    packet = SIPUtils::RTP::Packet.parse(rtp_data)
    packet.should_not be_nil

    if packet
      packet.payload_type.should eq(0)
      packet.sequence_number.should eq(12345)
      packet.payload.should eq(Bytes[0xDE, 0xAD, 0xBE, 0xEF])
    end
  end

  it "reject invalid RTP packet" do
    # Invalid packet - too short
    short_data = Bytes[0x80, 0x00, 0x30]
    packet = SIPUtils::RTP::Packet.parse(short_data)
    packet.should be_nil

    # Invalid version
    invalid_version = Bytes[0x40, 0x00, 0x30, 0x39, 0x00, 0x01, 0x09, 0x32, 0x12, 0x34, 0x56, 0x78]
    packet = SIPUtils::RTP::Packet.parse(invalid_version)
    packet.should be_nil
  end

  it "parse RTP packet with CSRC" do
    # RTP packet with CC=1 (one CSRC)
    rtp_data = Bytes[
      0x81, 0x00,             # V=2, P=0, X=0, CC=1, M=0, PT=0
      0x00, 0x01,             # Sequence number: 1
      0x00, 0x00, 0x00, 0x64, # Timestamp: 100
      0x11, 0x22, 0x33, 0x44, # SSRC
      0xAA, 0xBB, 0xCC, 0xDD, # CSRC[0]
      0x12, 0x34              # Payload: 2 bytes
    ]

    packet = SIPUtils::RTP::Packet.parse(rtp_data)
    packet.should_not be_nil

    if packet
      packet.payload.should eq(Bytes[0x12, 0x34])
    end
  end

  it "create RTP comfort noise packet" do
    sequence = 12345_u16
    timestamp = 8000_u32
    ssrc = 0x12345678_u32

    cn_packet = SIPUtils::RTP::Packet.create_comfort_noise(sequence, timestamp, ssrc)

    # Verify packet structure
    cn_packet.size.should eq(13) # 12 byte header + 1 byte payload

    # Verify RTP header
    cn_packet[0].should eq(0x80) # V=2, P=0, X=0, CC=0
    cn_packet[1].should eq(13)   # M=0, PT=13 (Comfort Noise)

    # Verify sequence number
    cn_packet[2].should eq(0x30) # 12345 >> 8
    cn_packet[3].should eq(0x39) # 12345 & 0xFF

    # Verify timestamp
    cn_packet[4].should eq(0x00) # 8000 >> 24
    cn_packet[5].should eq(0x00) # (8000 >> 16) & 0xFF
    cn_packet[6].should eq(0x1F) # (8000 >> 8) & 0xFF
    cn_packet[7].should eq(0x40) # 8000 & 0xFF

    # Verify SSRC
    cn_packet[8].should eq(0x12)  # ssrc >> 24
    cn_packet[9].should eq(0x34)  # (ssrc >> 16) & 0xFF
    cn_packet[10].should eq(0x56) # (ssrc >> 8) & 0xFF
    cn_packet[11].should eq(0x78) # ssrc & 0xFF

    # Verify comfort noise payload
    cn_packet[12].should eq(0x40) # Noise level -40 dBm0
  end
end
