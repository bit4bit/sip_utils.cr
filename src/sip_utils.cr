require "random"
require "digest"
require "socket"

module SIPUtils
  VERSION = "0.1.0"

  module Network
    class UA
      abstract class Tagger
        abstract def tag
        abstract def branch
        abstract def call_id
        abstract def cnonce
      end

      class DefaultTagger < Tagger
        def initialize
          @random = Random.new
        end

        def tag
          @random.hex(10)
        end

        def branch
          @random.hex(10)
        end

        def call_id
          @random.hex(10)
        end

        def cnonce
          @random.hex(10)
        end
      end

      def initialize(@tagger : Tagger = DefaultTagger.new)
        @cseq = 0
      end

      private def next_cseq
        @cseq += 1
      end

      def register(user : String, realm : String, password : String, via_address : String)
        SIP::Request.new("REGISTER", "sip:#{user}@#{realm}", "SIP/2.0", {
          "Via"            => "SIP/2.0/UDP #{via_address};branch=#{@tagger.branch}",
          "From"           => "<sip:#{user}@#{realm}>;tag=#{@tagger.tag}",
          "To"             => "<sip:#{user}@#{realm}>",
          "Call-ID"        => @tagger.call_id,
          "CSeq"           => "#{next_cseq} REGISTER",
          "Max-Forwards"   => "1",
          "Contact"        => "<sip:#{user}@#{via_address}>",
          "Expires"        => "3600",
          "Allow"          => "INVITE,ACK,BYE,CANCEL,REGISTER",
          "User-Agent"     => "SIPUtils",
          "Content-Length" => "0",
        }, private: {:user => user, :password => password, :realm => realm, :via_address => via_address})
      end

      def www_authenticate(request : SIPUtils::Network::SIP::Request, response : SIPUtils::Network::SIP::Response)
        req_authenticate = request.dup

        www_authenticate = response.headers["WWW-Authenticate"].to_s
        realm_match = www_authenticate.match(/realm="([^"]*)"/)
        nonce_match = www_authenticate.match(/nonce="([^"]*)"/)
        realm = realm_match.not_nil![1]
        nonce = nonce_match.not_nil![1]
        request.headers["CSeq"] = "#{next_cseq} REGISTER"
        cnonce = @tagger.cnonce
        authorization_uri = "sip:#{request.private[:realm]}"
        ha1_input = "#{request.private[:user]}:#{realm}:#{request.private[:password]}"
        ha2_input = "REGISTER:#{authorization_uri}"
        digest_user = Digest::MD5.hexdigest(ha1_input)
        digest_uri = Digest::MD5.hexdigest(ha2_input)
        response_input = "#{digest_user}:#{nonce}:00000001:#{cnonce}:auth:#{digest_uri}"
        digest_response = Digest::MD5.hexdigest(response_input)
        auth_header = "Digest username=\"#{request.private[:user]}\",realm=\"#{realm}\",nonce=\"#{nonce}\",uri=\"#{authorization_uri}\",response=\"#{digest_response}\",algorithm=MD5,qop=auth,nc=00000001,cnonce=\"#{cnonce}\""
        req_authenticate.headers["Authorization"] = auth_header
        req_authenticate
      end

      def answer_invite(request : SIPUtils::Network::SIP::Request, media_address : String, media_port : Int32, session_id : String, via_address : String, pcmu_rate = 8000) : SIPUtils::Network::SIP::Response
        sdp_body = String.build do |str|
          str << "v=0\r\n"
          str << "o=- #{session_id} #{session_id} IN IP4 #{media_address}\r\n"
          str << "s=SIPUtils\r\n"
          str << "c=IN IP4 #{media_address}\r\n"
          str << "t=0 0\r\n"
          str << "m=audio #{media_port} RTP/AVP 0\r\n"
          str << "a=rtpmap:0 PCMU/#{pcmu_rate}\r\n"
        end

        headers = SIPUtils::Network::SIP::Headers.new
        headers["Via"] = request.headers["Via"]
        headers["From"] = request.headers["From"]
        headers["To"] = request.headers["To"] + ";tag=#{@tagger.tag}"
        headers["Call-ID"] = request.headers["Call-ID"]
        headers["CSeq"] = request.headers["CSeq"]
        headers["Contact"] = "<sip:#{via_address}>"
        headers["Content-Type"] = "application/sdp"
        headers["Content-Length"] = sdp_body.bytesize.to_s

        SIPUtils::Network::SIP::Response.new(SIPUtils::Network::SIP::Status::Ok, 200, "SIP/2.0", headers, sdp_body)
      end

      def answer_bye(request : SIPUtils::Network::SIP::Request, via_address : String) : SIPUtils::Network::SIP::Response
        headers = SIPUtils::Network::SIP::Headers.new
        headers["Via"] = request.headers["Via"]
        headers["From"] = request.headers["From"]
        headers["To"] = request.headers["To"]
        headers["Call-ID"] = request.headers["Call-ID"]
        headers["CSeq"] = request.headers["CSeq"]
        headers["Contact"] = "<sip:#{via_address}>"
        headers["Content-Length"] = "0"

        SIPUtils::Network::SIP::Response.new(SIPUtils::Network::SIP::Status::Ok, 200, "SIP/2.0", headers)
      end

      def parse_via_address(request : SIPUtils::Network::SIP::Request) : Socket::IPAddress
        via = request.headers["Via"].not_nil!
        match = via.match(/UDP\s+([^\s:]+):(\d+)/).not_nil!
        host = match[1]
        port = match[2].to_i

        Socket::IPAddress.new(host.not_nil!, port.not_nil!)
      end
    end

    def self.encode(message)
      case message
      when SIP::Request
        String.build do |str|
          str << message.method
          str << " "
          str << message.uri
          str << " "
          str << message.version
          str << "\r\n"

          message.headers.each do |key, value|
            str << key
            str << ": "
            str << value
            str << "\r\n"
          end

          str << "\r\n"
          str << message.body if message.body
        end
      when SIP::Response
        String.build do |str|
          str << message.version
          str << " "
          str << message.status_code
          str << " "
          str << message.status.to_s.upcase
          str << "\r\n"

          message.headers.each do |key, value|
            str << key
            str << ": "
            str << value
            str << "\r\n"
          end

          str << "\r\n"
          str << message.body if message.body
        end
      else
        raise SIP::SIPError.new("Unsupported message type")
      end
    end
  end

  class Network::SIP(T)
    alias Headers = Hash(String, String)
    enum Status
      Ok = 200
    end

    class SIPError < Exception
      def initialize(message)
        super(message)
      end
    end

    alias Private = Hash(Symbol, String)

    class Request
      getter :method, :uri, :version, :headers, :body, :private

      def initialize(@method : String, @uri : String, @version = "SIP/2.0", @headers = Headers.new, @body : String? = nil, @private = Private.new)
      end

      def self.parse_first_line(io : IO)
        line = io.gets(4096, chomp: true)
        raise SIPError.new("can't parse response") unless line

        pieces = line.split(3)
        raise SIPError.new("Invalid SIP response") unless pieces.size == 3

        pieces
      end

      def self.valid?(pieces)
        pieces[2] == "SIP/2.0"
      end

      def self.from_io(pieces, io : IO)
        SIP.parse_headers_and_body(io) do |headers, body|
          method = pieces[0]
          uri = pieces[1]

          new(method: method, uri: uri, version: pieces[2], headers: headers, body: body)
        end
      end
    end

    class Response
      getter :status, :version, :status_code, :headers, :body, :private

      def initialize(@status : Status, @status_code : Int32, @version = "SIP/2.0", @headers = Headers.new, @body : String? = nil, @private = Private.new)
      end

      def self.parse_first_line(io : IO)
        line = io.gets(4096, chomp: true)
        raise SIPError.new("can't parse response") unless line

        pieces = line.split(3)
        raise SIPError.new("Invalid SIP response") unless pieces.size == 3

        pieces
      end

      def self.valid?(pieces)
        pieces[0] == "SIP/2.0"
      end

      def self.from_io(pieces, io : IO)
        SIP.parse_headers_and_body(io) do |headers, body|
          status_code = pieces[1].to_i?

          unless status_code && 100 <= status_code < 600
            raise SIPError.new("Invalid SIP status code")
          end

          new(status: Status.new(status_code), status_code: status_code, version: pieces[0], headers: headers, body: body)
        end
      end
    end

    class SDP
      getter :version, :origin, :session_name, :connection, :time, :media, :attributes

      def initialize(@version : Int32, @origin : String, @session_name : String, @connection : String, @time : String, @media : String, @attributes : Array(String))
      end

      def self.parse_first_line(io : IO)
        [] of String
      end

      def self.valid?(pieces)
        true
      end

      def self.from_io(pieces, io : IO)
        version = 0
        origin = ""
        session_name = ""
        connection = ""
        time = ""
        media = ""
        attributes = [] of String

        content = io.gets_to_end
        lines = content.split(/\r?\n/)

        lines.each do |line|
          next if line.empty?

          case line[0]
          when 'v'
            version = line[2..-1].to_i
          when 'o'
            origin = line[2..-1]
          when 's'
            session_name = line[2..-1]
          when 'c'
            connection = line[2..-1]
          when 't'
            time = line[2..-1]
          when 'm'
            media = line[2..-1]
          when 'a'
            attributes << line[2..-1]
          end
        end

        new(version: version, origin: origin, session_name: session_name, connection: connection, time: time, media: media, attributes: attributes)
      end
    end

    def self.valid?(io : IO)
      pieces = T.parse_first_line(io)
      T.valid?(pieces)
    end

    def self.parse(io : IO) : T
      pieces = T.parse_first_line(io)
      T.from_io(pieces, io)
    end

    def self.parse_headers_and_body(io, &)
      headers = Headers.new

      while line = io.gets(4096, chomp: true)
        break if line.empty?

        colon_index = line.index(':')
        raise SIPError.new("Invalid header format") unless colon_index

        key = line[0...colon_index].strip
        value = line[colon_index + 1..-1].strip
        headers[key] = value
      end

      body = ""
      content_length = headers["Content-Length"]?.try(&.to_i) || 0
      if content_length > 0
        buffer = Bytes.new(content_length)
        io.read_fully(buffer)
        body = String.new(buffer)
      end

      yield headers, body
    end
  end

  module RTP
    class Packet
      getter :payload_type, :sequence_number, :payload

      def initialize(@payload_type : UInt8, @sequence_number : UInt16, @payload : Bytes)
      end

      def self.parse(data : Bytes) : Packet?
        return nil if data.size < 12

        version = (data[0] >> 6) & 0x03
        return nil if version != 2

        csrc_count = data[0] & 0x0F
        payload_type = data[1] & 0x7F
        sequence_number = ((data[2].to_u16 << 8) | data[3].to_u16)

        header_size = 12 + (csrc_count * 4)
        return nil if data.size < header_size

        payload = data[header_size, data.size - header_size]

        new(payload_type.to_u8, sequence_number, payload)
      end

      def self.create_comfort_noise(sequence_number : UInt16, timestamp : UInt32, ssrc : UInt32) : Bytes
        header = Bytes.new(12)

        # Version=2, Padding=0, Extension=0, CSRC=0, Marker=0, PT=13 (CN)
        header[0] = 0x80_u8
        header[1] = 13_u8 # Comfort Noise payload type

        # Sequence number (big endian)
        header[2] = ((sequence_number >> 8) & 0xFF).to_u8
        header[3] = (sequence_number & 0xFF).to_u8

        # Timestamp (big endian)
        header[4] = ((timestamp >> 24) & 0xFF).to_u8
        header[5] = ((timestamp >> 16) & 0xFF).to_u8
        header[6] = ((timestamp >> 8) & 0xFF).to_u8
        header[7] = (timestamp & 0xFF).to_u8

        # SSRC (big endian)
        header[8] = ((ssrc >> 24) & 0xFF).to_u8
        header[9] = ((ssrc >> 16) & 0xFF).to_u8
        header[10] = ((ssrc >> 8) & 0xFF).to_u8
        header[11] = (ssrc & 0xFF).to_u8

        # Comfort noise payload (1 byte with noise level)
        payload = Bytes[0x40_u8] # -40 dBm0 noise level

        header + payload
      end
    end
  end
end
