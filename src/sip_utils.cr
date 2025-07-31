module SIPUtils
  VERSION = "0.1.0"

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
      getter :method, :uri, :version, :headers

      def initialize(@method : String, @uri : String, @version = "SIP/2.0", @headers = Headers.new)
      end

      def self.valid?(pieces)
        pieces[2] == "SIP/2.0"
      end

      def self.from_io(pieces, io : IO)
        SIP.parse_headers_and_body(io) do |headers, body|
          method = pieces[0]
          uri = pieces[1]

          new(method: method, uri: uri, version: pieces[2], headers: headers)
        end
      end
    end

    class Response
      getter :status, :version, :status_code, :headers

      def initialize(@status : Status, @status_code : Int32, @version = "SIP/2.0", @headers = Headers.new)
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

          new(status: Status.new(status_code), status_code: status_code, version: pieces[0], headers: headers)
        end
      end
    end

    def self.valid?(io : IO)
      line = io.gets(4096, chomp: true)
      raise SIPError.new("can't parse response") unless line

      pieces = line.split(3)
      raise SIPError.new("Invalid SIP response") unless pieces.size == 3

      T.valid?(pieces)
    end

    def self.parse(io : IO) : T
      line = io.gets(4096, chomp: true)
      raise SIPError.new("can't parse response") unless line

      pieces = line.split(3)
      raise SIPError.new("Invalid SIP response") unless pieces.size == 3

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

      yield headers, nil
    end
  end
end
