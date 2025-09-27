# register, receive a call, and dump audio to file
# TODO compile statically of  https://github.com/irtlab/rtptools.git dumping audio?
#
# RAW TO WAV
# sox -t raw -r 8000 -e mu-law -c 1 /tmp/media_dumper.raw /tmp/media_dumper.wav
require "uuid"
require "log"
require "socket"
require "../src/sip_utils.cr"

module Random
  LEGIBLE_ALPHANUM = "234679ACDEFGHJKMNPQRTWXYZabcdefghjkmnopqrstwxy"

  def self.secure(size : Int = 10, charset : String = LEGIBLE_ALPHANUM)
    charset = charset.chars

    String.build(size) do |io|
      size.times do
        io << charset.sample(1).first
      end
    end
  end

  def self.secure_number(size : Int = 10)
    String.build(size) do |io|
      size.times do
        io << (rand(10)).to_s
      end
    end
  end
end

class SimplePhone
  abstract class StateBehavior
    def next
      raise NotImplementedError.new("next() must be implemented")
    end
  end

  class State::Idle < StateBehavior
    def next
      self
    end
  end

  class State::Accepting < StateBehavior
    def initialize(@inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @root_request : SIPUtils::Network::SIP::Request)
    end

    def next
      message, _ = @inbound_socket.receive(8096)
      request = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).parse(IO::Memory.new(message))

      if request.method != "INVITE"
        Log.debug { "Ignoring non-INVITE method: #{request.method}" }
        return self
      end

      Log.info { "Received INVITE from #{request.headers["From"]}" }
      Log.debug { "Received INVITE body: #{request.inspect}" }
      # Parse SDP from INVITE body
      body = request.body || ""
      puts body
      sdp = SIPUtils::Network::SIP(SIPUtils::Network::SIP::SDP).parse(IO::Memory.new(body))

      # Extract media port from SDP
      media_parts = sdp.media.split(" ")
      remote_media_port = media_parts[1].to_i

      # Create our media port
      media_socket = UDPSocket.new
      media_socket.bind("172.15.238.1", 0)
      media_socket.read_timeout = 100.milliseconds
      local_media_port = media_socket.local_address.port

      # Create SDP response
      sdp_body = String.build do |str|
        str << "v=0\r\n"
        str << "o=- #{Random.secure_number} #{Random.secure_number} IN IP4 172.15.238.1\r\n"
        str << "s=-\r\n"
        str << "c=IN IP4 172.15.238.1\r\n"
        str << "t=0 0\r\n"
        str << "m=audio #{local_media_port} RTP/AVP 0\r\n"
        str << "a=rtpmap:0 PCMU/8000\r\n"
      end

      # Create response headers
      headers = SIPUtils::Network::SIP::Headers.new
      headers["Via"] = request.headers["Via"]
      headers["From"] = request.headers["From"]
      headers["To"] = request.headers["To"] + ";tag=#{Random.secure}"
      headers["Call-ID"] = request.headers["Call-ID"]
      headers["CSeq"] = request.headers["CSeq"]
      headers["Contact"] = "<sip:#{@inbound_socket.local_address}>"
      headers["Content-Type"] = "application/sdp"
      headers["Content-Length"] = sdp_body.bytesize.to_s

      # Create 200 OK response with body
      response = SIPUtils::Network::SIP::Response.new(SIPUtils::Network::SIP::Status::Ok, 200, "SIP/2.0", headers, sdp_body)

      # Send 200 OK
      @outbound_socket.send(SIPUtils::Network.encode(response))
      Log.info { "Sent 200 OK response with media port #{local_media_port}" }

      # Transition to InCall state and return it
      State::InCall.new(@inbound_socket, @outbound_socket, @root_request, media_socket)
    end
  end

  class State::InCall < StateBehavior
    def initialize(@inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @root_request : SIPUtils::Network::SIP::Request, @media_socket : UDPSocket)
      @stop = false
      @started = false
    end

    def start
      return if @started
      @started = true
      spawn do
        Log.debug { "Starting media dump to /tmp/media_dumper.raw on port #{@media_socket.local_address.port}" }
        begin
          File.open("/tmp/media_dumper.raw", "wb") do |file|
            buffer = Bytes.new(1500)
            packet_count = 0
            loop do
              break if @stop

              begin
                bytes_read, sender_addr = @media_socket.receive(buffer)
                rtp_packet = SIPUtils::RTP::Packet.parse(buffer[0, bytes_read])
                if rtp_packet
                  file.write(rtp_packet.payload)
                  Log.debug { "Extracted RTP payload: #{rtp_packet.payload.size} bytes (PT: #{rtp_packet.payload_type}, Seq: #{rtp_packet.sequence_number})" }
                else
                  Log.debug { "Failed to parse RTP packet, writing raw data" }
                  file.write(buffer[0, bytes_read])
                end
                file.flush
                packet_count += 1
                if packet_count % 100 == 0
                  Log.debug { "Received #{packet_count} media packets (#{bytes_read} bytes from #{sender_addr})" }
                else
                  Log.debug { "Received media packet (#{bytes_read} bytes from #{sender_addr})" }
                end
              rescue
                break if @stop
              end
            end
          end
          Log.debug { "Media dumping stopped" }
        rescue ex : Exception
          Log.error { "Media dumping error: #{ex.message}" }
        end
      end
    end

    def next
      start
      # Wait for ACK or other messages
      begin
        message, _ = @inbound_socket.receive

        # Try to parse as SIP request first, then response if that fails
        begin
          request = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).parse(IO::Memory.new(message))

          case request.method
          when "ACK"
            Log.debug { "Received ACK, call established" }
          when "BYE"
            Log.debug { "Received BYE, ending call" }

            # Send 200 OK for BYE
            headers = SIPUtils::Network::SIP::Headers.new
            headers["Via"] = request.headers["Via"]
            headers["From"] = request.headers["From"]
            headers["To"] = request.headers["To"]
            headers["Call-ID"] = request.headers["Call-ID"]
            headers["CSeq"] = request.headers["CSeq"]
            headers["Content-Length"] = "0"

            response = SIPUtils::Network::SIP::Response.new(SIPUtils::Network::SIP::Status::Ok, 200, "SIP/2.0", headers)
            @outbound_socket.send(SIPUtils::Network.encode(response))
            @stop = true
            sleep(1.second)
            @media_socket.close
            Log.info { "Call ended, media dumping stopped" }

            return State::Accepting.new(@inbound_socket, @outbound_socket, @root_request)
          else
            Log.debug { "Ignoring message during call: #{request.method}" }
          end
        rescue
          # Might be a response, ignore it
          Log.debug { "Ignoring SIP response during call" }
        end
      rescue ex : Exception
        Log.error { "Error handling call message: #{ex.message}" }
      end

      self
    end
  end

  class State::Registering < StateBehavior
    def initialize(@inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @user : String, @password : String, @realm : String)
      @action = "send_register"
    end

    def next
      request = SIPUtils::Network::SIP::Request.new("REGISTER", "sip:#{@realm}", "SIP/2.0")
      request.headers["Via"] = "SIP/2.0/UDP #{@inbound_socket.local_address}"
      request.headers["Max-Forwards"] = "1"
      request.headers["To"] = "<sip:#{@user}@#{@realm}>"
      request.headers["From"] = "<sip:#{@user}@#{@realm}>;tag=#{Random.secure}"
      request.headers["Call-ID"] = UUID.v4.hexstring
      request.headers["CSeq"] = "1 REGISTER"
      request.headers["Contact"] = "<sip:#{@user}@#{@inbound_socket.local_address}>;expires=3600"
      request.headers["User-Agent"] = "SimplePhone"
      request.headers["Allow"] = "INVITE,ACK,BYE,CANCEL,REGISTER"
      request.headers["Content-Length"] = "0"
      Log.debug { "SimplePhone: sending request #{request.inspect}" }
      @outbound_socket.send(SIPUtils::Network.encode(request))
      @action = "wait_authentication"

      message, _ = @inbound_socket.receive
      response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new(message))

      if response.status_code != 401
        raise "not implemented logic for response authentication code #{response.status_code}"
      end

      www_authenticate = response.headers["WWW-Authenticate"]
      realm_match = www_authenticate.match(/realm="([^"]*)"/)
      nonce_match = www_authenticate.match(/nonce="([^"]*)"/)
      realm = realm_match.not_nil![1]
      nonce = nonce_match.not_nil![1]
      request.headers["CSeq"] = "2 REGISTER"
      cnonce = Random.secure
      authorization_uri = "sip:#{@realm}"
      ha1_input = "#{@user}:#{realm}:#{@password}"
      ha2_input = "REGISTER:#{authorization_uri}"
      digest_user = Digest::MD5.hexdigest(ha1_input)
      digest_uri = Digest::MD5.hexdigest(ha2_input)
      response_input = "#{digest_user}:#{nonce}:00000001:#{cnonce}:auth:#{digest_uri}"
      digest_response = Digest::MD5.hexdigest(response_input)
      auth_header = "Digest username=\"#{@user}\",realm=\"#{realm}\",nonce=\"#{nonce}\",uri=\"#{authorization_uri}\",response=\"#{digest_response}\",algorithm=MD5,qop=auth,nc=00000001,cnonce=\"#{cnonce}\""
      request.headers["Authorization"] = auth_header

      @outbound_socket.send(SIPUtils::Network.encode(request))

      message, _ = @inbound_socket.receive
      response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new(message))

      if response.status_code == 200
        Log.debug { "Registration successful authentication! #{response.inspect}" }
        return State::Accepting.new(@inbound_socket, @outbound_socket, request)
      end

      self
    end
  end

  def initialize
    @state = State::Idle.new
  end

  def setup(server_ip, server_port)
    @inbound_socket = UDPSocket.new
    @inbound_socket.not_nil!.bind("172.15.238.1", 5066)
    @outbound_socket = UDPSocket.new
    @outbound_socket.not_nil!.connect(server_ip, server_port)
  end

  def register(user, password, realm)
    @state = State::Registering.new(@inbound_socket.not_nil!, @outbound_socket.not_nil!, user, password, realm)
  end

  def next
    @state = @state.next
  end
end

Log.setup_from_env(default_level: Log::Severity::Debug)

phone = SimplePhone.new
phone.setup("172.15.238.10", 5060)
phone.register("1001", "clave", "172.15.238.10")
# registration process
phone.next

# wait for incoming call and handle it
loop do
  phone.next
end
