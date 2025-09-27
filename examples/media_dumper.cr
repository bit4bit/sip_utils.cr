# register, receive a call, and dump audio to file
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
      message, _ = @inbound_socket.receive
      response = SIPUtils::Network::SIP(SIPUtils::Network::SIP::Response).parse(IO::Memory.new(message))

      if response.method != "INVITE"
        raise "Unexpected method: #{response.method}"
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
        @state = State::Accepting.new(@inbound_socket.not_nil!, @outbound_socket.not_nil!, request)
      end

      Log.debug { "Registration successful authentication! #{response.inspect}" }
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
# request
phone.next
# accept call
phone.next
