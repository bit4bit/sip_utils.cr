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
    def initialize(@ua : SIPUtils::Network::UA, @inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @root_request : SIPUtils::Network::SIP::Request)
    end

    def next(context : Context)
      message, _ = @inbound_socket.receive(8096)
      request = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Request).parse(IO::Memory.new(message))

      if request.method != "INVITE"
        Log.debug { "Ignoring non-INVITE method: #{request.method}" }
        return self
      end

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

      response = @ua.answer_invite(request: request, media_address: media_socket.local_address.address.to_s, media_port: local_media_port, session_id: "0", via_address: @inbound_socket.local_address.to_s)

      Log.debug { "Answering with response: #{SIPUtils::Network.encode(response)}" }

      # Send 200 OK
      @outbound_socket.send(SIPUtils::Network.encode(response))
      Log.info { "Sent 200 OK response with media port #{local_media_port}" }

      # Transition to InCall state and return it
      State::InCall.new(@ua, @inbound_socket, @outbound_socket, @root_request, media_socket, remote_media_ip, remote_media_port)
    end
  end

  class State::InCall < StateBehavior
    @cn_sequence : UInt16
    @cn_timestamp : UInt32
    @cn_ssrc : UInt32
    @last_packet_time : Time::Span

    def initialize(@ua : SIPUtils::Network::UA, @inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @root_request : SIPUtils::Network::SIP::Request, @media_socket : UDPSocket, @remote_ip : String, @remote_port : Int32)
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

            return State::Accepting.new(@ua, @inbound_socket, @outbound_socket, @root_request)
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
              ws.send(buffer[0, bytes_read])
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
    def initialize(@ua : SIPUtils::Network::UA, @inbound_socket : UDPSocket, @outbound_socket : UDPSocket, @user : String, @password : String, @realm : String)
      @action = "send_register"
    end

    def next(context : Context)
      request = @ua.register(user: @user, password: @password, realm: @realm, via_address: @inbound_socket.local_address.to_s)
      Log.debug { "SimplePhone: sending request #{SIPUtils::Network.encode(request)}" }
      @outbound_socket.send(SIPUtils::Network.encode(request))
      @action = "wait_authentication"
      message, _ = @inbound_socket.receive(8096)
      response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new(message))

      if response.status_code != 401
        raise "not implemented logic for response authentication code #{response.status_code}"
      end

      Log.debug { "SimplePhone: received response #{response.inspect}" }
      with_authentication = @ua.www_authenticate(request, response)
      @outbound_socket.send(SIPUtils::Network.encode(with_authentication))

      message, _ = @inbound_socket.receive
      response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new(message))

      if response.status_code == 200
        Log.debug { "Registration successful authentication! #{response.inspect}" }
        return State::Accepting.new(@ua, @inbound_socket, @outbound_socket, request)
      end

      self
    end
  end

  def initialize
    @state = State::Idle.new
    tagger = SIPUtils::Network::UA::DefaultTagger.new
    @ua = SIPUtils::Network::UA.new(tagger: tagger)
  end

  def setup(server_ip, server_port, inbound_ip)
    @inbound_socket = UDPSocket.new
    @inbound_socket.not_nil!.bind(inbound_ip, 0)
    @outbound_socket = UDPSocket.new
    @outbound_socket.not_nil!.connect(server_ip, server_port)
  end

  def register(user, password, realm)
    @state = State::Registering.new(@ua, @inbound_socket.not_nil!, @outbound_socket.not_nil!, user, password, realm)
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
