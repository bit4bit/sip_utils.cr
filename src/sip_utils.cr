module SIPUtils
  VERSION = "0.1.0"

  module Network
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
          str << message.status
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

    class Request
      getter :method, :uri, :version, :headers, :body

      def initialize(@method : String, @uri : String, @version = "SIP/2.0", @headers = Headers.new, @body : String? = nil)
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
      getter :status, :version, :status_code, :headers, :body

      def initialize(@status : Status, @status_code : Int32, @version = "SIP/2.0", @headers = Headers.new, @body : String? = nil)
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
    end
  end
end
