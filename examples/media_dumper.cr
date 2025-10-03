# register, receive a call, and dump audio to file
# TODO compile statically of  https://github.com/irtlab/rtptools.git dumping audio?
#
# RAW TO WAV
# sox -t raw -r 8000 -e mu-law -c 1 /tmp/media_dumper.raw /tmp/media_dumper.wav
require "option_parser"
require "uuid"
require "log"
require "socket"
require "http/web_socket"
require "../src/sip_utils.cr"

module WAVEncoder
  def self.write_header(file : File, data_size : UInt32)
    # RIFF header
    file.write_bytes(0x46464952_u32, IO::ByteFormat::LittleEndian)     # "RIFF"
    file.write_bytes(36_u32 + data_size, IO::ByteFormat::LittleEndian) # File size - 8
    file.write_bytes(0x45564157_u32, IO::ByteFormat::LittleEndian)     # "WAVE"

    # fmt chunk
    file.write_bytes(0x20746d66_u32, IO::ByteFormat::LittleEndian) # "fmt "
    file.write_bytes(18_u32, IO::ByteFormat::LittleEndian)         # fmt chunk size (16 + 2 for μ-law)
    file.write_bytes(7_u16, IO::ByteFormat::LittleEndian)          # μ-law format
    file.write_bytes(1_u16, IO::ByteFormat::LittleEndian)          # Mono
    file.write_bytes(8000_u32, IO::ByteFormat::LittleEndian)       # 8kHz sample rate
    file.write_bytes(8000_u32, IO::ByteFormat::LittleEndian)       # Byte rate
    file.write_bytes(1_u16, IO::ByteFormat::LittleEndian)          # Block align
    file.write_bytes(8_u16, IO::ByteFormat::LittleEndian)          # 8 bits per sample
    file.write_bytes(0_u16, IO::ByteFormat::LittleEndian)          # Extra param size

    # data chunk
    file.write_bytes(0x61746164_u32, IO::ByteFormat::LittleEndian) # "data"
    file.write_bytes(data_size, IO::ByteFormat::LittleEndian)      # Data size
  end

  def self.update_header(file : File, data_size : UInt32)
    file.seek(4, IO::Seek::Set)
    file.write_bytes(36_u32 + data_size, IO::ByteFormat::LittleEndian)
    file.seek(42, IO::Seek::Set)
    file.write_bytes(data_size, IO::ByteFormat::LittleEndian)
  end
end

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
  class Context
    getter :media_dump_url

    def initialize(@media_dump_url : URI)
      @media_dump_url = media_dump_url
    end
  end

  abstract class StateBehavior
    def next(context : Context)
      raise NotImplementedError.new("next() must be implemented")
    end
  end

  class State::Idle < StateBehavior
    def next(context : Context)
      self
    end
  end

  class State::Accepting < StateBehavior
    def initialize(context @inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @root_request : SIPUtils::Network::SIP::Request)
    end

    def next(context : Context)
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

      # Extract remote IP from SDP connection
      connection_parts = sdp.connection.split(" ")
      remote_media_ip = connection_parts[2]

      # Create our media port
      media_socket = UDPSocket.new
      media_socket.bind(@inbound_socket.local_address.address, 0)
      media_socket.read_timeout = 100.milliseconds
      local_media_port = media_socket.local_address.port

      # Create SDP response
      sdp_body = String.build do |str|
        str << "v=0\r\n"
        str << "o=- #{Random.secure_number} #{Random.secure_number} IN IP4 #{@inbound_socket.local_address.address}\r\n"
        str << "s=-\r\n"
        str << "c=IN IP4 #{@inbound_socket.local_address.address}\r\n"
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
      State::InCall.new(@inbound_socket, @outbound_socket, @root_request, media_socket, remote_media_ip, remote_media_port)
    end
  end

  class State::InCall < StateBehavior
    @cn_sequence : UInt16
    @cn_timestamp : UInt32
    @cn_ssrc : UInt32
    @last_packet_time : Time::Span

    def initialize(@inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @root_request : SIPUtils::Network::SIP::Request, @media_socket : UDPSocket, @remote_ip : String, @remote_port : Int32)
      @stop = false
      @started = false
      @cn_sequence = 1_u16
      @cn_timestamp = 0_u32
      @cn_ssrc = Random.rand(UInt32)
      @last_packet_time = Time.monotonic
    end

    def start(context : Context)
      return if @started
      @started = true

      # Start comfort noise sender
      spawn do
        Log.debug { "Starting comfort noise sender to #{@remote_ip}:#{@remote_port}" }
        begin
          loop do
            break if @stop

            # Send comfort noise every 20ms if no recent activity
            current_time = Time.monotonic
            if current_time - @last_packet_time > 100.milliseconds
              cn_packet = SIPUtils::RTP::Packet.create_comfort_noise(@cn_sequence, @cn_timestamp, @cn_ssrc)
              @media_socket.send(cn_packet, to: Socket::IPAddress.new(@remote_ip, @remote_port))
              @cn_sequence += 1
              @cn_timestamp += 160 # 20ms at 8kHz
              Log.debug { "Sent comfort noise packet (seq: #{@cn_sequence - 1})" }
            end

            sleep(20.milliseconds)
          end
        rescue ex : Exception
          Log.error { "Comfort noise sender error: #{ex.message}" }
        end
      end

      case context.media_dump_url.scheme
      when "file"
        dump_to_file(context.media_dump_url.path)
      when "ws", "wss"
        dump_to_websocket(context.media_dump_url)
      end
    end

    def next(context : Context)
      start(context)
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

    def dump_to_file(media_dump_path)
      spawn do
        Log.debug { "Starting media dump to #{media_dump_path} on port #{@media_socket.local_address.port}" }
        begin
          File.open(media_dump_path, "wb") do |file|
            # Write initial WAV header with placeholder data size
            WAVEncoder.write_header(file, 0_u32)
            data_size = 0_u32

            buffer = Bytes.new(1500)
            packet_count = 0
            loop do
              break if @stop

              begin
                bytes_read, sender_addr = @media_socket.receive(buffer)
                @last_packet_time = Time.monotonic # Update last packet time
                rtp_packet = SIPUtils::RTP::Packet.parse(buffer[0, bytes_read])
                if rtp_packet
                  file.write(rtp_packet.payload)
                  data_size += rtp_packet.payload.size
                  Log.debug { "Extracted RTP payload: #{rtp_packet.payload.size} bytes (PT: #{rtp_packet.payload_type}, Seq: #{rtp_packet.sequence_number})" }
                else
                  Log.debug { "Failed to parse RTP packet, writing raw data" }
                  file.write(buffer[0, bytes_read])
                  data_size += bytes_read
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

            # Update WAV header with actual data size
            WAVEncoder.update_header(file, data_size)
          end
          Log.debug { "Media dumping stopped, WAV file saved to #{media_dump_path}" }
        rescue ex : Exception
          Log.error { "Media dumping error: #{ex.message}" }
        end
      end
    end

    def dump_to_websocket(websocket_url : URI)
      spawn do
        Log.debug { "Starting media dump to WebSocket #{websocket_url} on port #{@media_socket.local_address.port}" }
        begin
          ws = HTTP::WebSocket.new(websocket_url)
          buffer = Bytes.new(1500)
          packet_count = 0
          loop do
            break if @stop

            begin
              bytes_read, sender_addr = @media_socket.receive(buffer)
              @last_packet_time = Time.monotonic
              rtp_packet = SIPUtils::RTP::Packet.parse(buffer[0, bytes_read])
              if rtp_packet
                ws.send(rtp_packet.payload)
                Log.debug { "Sent RTP payload to WebSocket: #{rtp_packet.payload.size} bytes (PT: #{rtp_packet.payload_type}, Seq: #{rtp_packet.sequence_number})" }
              else
                Log.debug { "Failed to parse RTP packet, sending raw data to WebSocket" }
                ws.send(buffer[0, bytes_read])
              end
              packet_count += 1
              if packet_count % 100 == 0
                Log.debug { "Sent #{packet_count} media packets to WebSocket (#{bytes_read} bytes from #{sender_addr})" }
              else
                Log.debug { "Sent media packet to WebSocket (#{bytes_read} bytes from #{sender_addr})" }
              end
            rescue
              break if @stop
            end
          end
          ws.close
          Log.debug { "Media dumping to WebSocket stopped" }
        rescue ex : Exception
          Log.error { "WebSocket media dumping error: #{ex.message}" }
        end
      end
    end
  end

  class State::Registering < StateBehavior
    def initialize(@inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @user : String, @password : String, @realm : String)
      @action = "send_register"
    end

    def next(context : Context)
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

  def setup(server_ip, server_port, inbound_ip)
    @inbound_socket = UDPSocket.new
    @inbound_socket.not_nil!.bind(inbound_ip, 0)
    @outbound_socket = UDPSocket.new
    @outbound_socket.not_nil!.connect(server_ip, server_port)
  end

  def register(user, password, realm)
    @state = State::Registering.new(@inbound_socket.not_nil!, @outbound_socket.not_nil!, user, password, realm)
  end

  def next(context : Context)
    @state = @state.next(context)
  end
end

Log.setup_from_env(default_level: Log::Severity::Debug)

# Default values
server_ip = "172.15.238.10"
server_port = 5060
inbound_ip = "172.15.238.1"
user = "1001"
password = "clave"
realm = "172.15.238.10"
media_dump_url = "file:///tmp/media_dump.wav"

# Parse command line arguments
OptionParser.parse do |parser|
  parser.banner = "Usage: simple_phone [options]"

  parser.on("-s HOST", "--server=HOST", "SIP server IP address") { |host| server_ip = host }
  parser.on("-p PORT", "--port=PORT", "SIP server port") { |port| server_port = port.to_i }
  parser.on("-i IP", "--inbound=IP", "Local IP address to bind to") { |ip| inbound_ip = ip }
  parser.on("-u USER", "--user=USER", "SIP username") { |u| user = u }
  parser.on("-w PASSWORD", "--password=PASSWORD", "SIP password") { |pw| password = pw }
  parser.on("-r REALM", "--realm=REALM", "SIP realm") { |r| realm = r }
  parser.on("-m URL", "--media=URL", "Media dump URL (file:// or ws://)") { |url| media_dump_url = url }
  parser.on("-h", "--help", "Show this help") do
    puts parser
    exit
  end
end

ctx = SimplePhone::Context.new(media_dump_url: URI.parse(media_dump_url))
phone = SimplePhone.new
phone.setup(server_ip: server_ip, server_port: server_port, inbound_ip: inbound_ip)
phone.register(user, password, realm)
loop do
  phone.next(ctx)
end
