#!/usr/bin/env ruby

require "socket"
require "digest"
require "base64"
require "optparse"

module WebSockets
  class << self
    attr_writer :verbose, :debug

    public
      def info(message)
        puts "#{prefix}#{message}" if @verbose
      end

      def debug(message)
        puts "#{prefix}#{message}" if @debug
      end

    private
      def prefix
        @debug ? ("[0x%08x] " % Thread.current.object_id) : ""
      end
  end

  # Raised when the WebSocket connection is aborted because of protocol error.
  class ConnectionAborted < StandardError; end

  # Raised when the WebSocket connection is (gracefully) terminated by the
  # client.
  class ClientTerminated  < StandardError; end

  # Implements a WebSocket server according to the
  # draft-hixie-thewebsocketprotocol-76 version of the WebSocket protocol. All
  # references to sections and steps inside the class refer to this draft.
  #
  # See http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76.
  class WebSocket
    attr_reader :socket, :protocol, :resource_name, :fields

    public
      def initialize(socket, protocol)
        @socket = socket
        @protocol = protocol
        @handshaked = false
        @terminated = false
      end

      def handshaked?
        @handshaked
      end

      def terminated?
        @terminated
      end

      def handshake
        raise "Already handshaked." if @handshaked
        raise "Already terminated." if @terminated

        receive_client_handshake
        send_server_handshake

        @handshaked = true
      end

      def read_frame
        raise "Not yet handshaked." unless @handshaked
        raise "Already terminated." if @terminated

        # Implements the first set of steps in section 5.3.

        # Step 1
        type = read_bytes(1)

        # Step 2
        if type == "\x00"
          raw_data = ""
          while (b = read_bytes(1)) != "\xFF"
            raw_data += b
          end
          raw_data
        elsif type == "\xFF"
          b = read_bytes(1)
          if b == "\x00"
            terminate_by_client
          else
            abort_connection "Invalid frame termination byte: 0x%02x." % b[0]
          end
        else
          abort_connection "Invalid frame type: 0x%02x." % type[0]
        end
      end

      def write_frame(data)
        raise "Not yet handshaked." unless @handshaked
        raise "Already terminated." if @terminated

        # Implements the second set of steps in section 5.3.

        # Steps 1-3
        write_bytes("\x00#{data}\xFF")
      end

      def terminate
        raise "Not yet handshaked." unless @handshaked
        raise "Already terminated." if @terminated

        # Implements the final set of steps in section 5.3.

        # Step 1
        write_bytes("\xFF\x00")

        # In Step 2, the specification wants us to wait until the client sends
        # its "\xFF\x00" sequence or until a timeout expires. To avoid
        # introducing more state, we say that the timeout is 0 (= it just
        # expired :-) and proceed further.
        #
        # This is probably not 100% in line with the spirit of the
        # specification, but I don't see how this could cause any significant
        # problems.

        # Step 3
        @socket.close

        @terminated = true
      end

    private
      def read_line
        line = @socket.gets("\r\n")
        WebSockets.debug "WebSocket read line: #{line}"
        line
      end

      def read_bytes(n)
        bytes = @socket.read(n)
        WebSockets.debug "WebSocket read #{n} bytes: #{bytes.inspect}"
        bytes
      end

      def write_line(line)
        @socket.write("#{line}\r\n")
        WebSockets.debug "WebSocket write line: #{line}"
      end

      def write_bytes(bytes)
        @socket.write(bytes)
        WebSockets.debug "WebSocket write #{bytes.size} bytes: #{bytes.inspect}"
      end

      def abort_connection
        @socket.close
        @terminated = true

        raise ConnectionAborted, "Connection aborted: #{reason}"
      end

      def terminate_by_client
        @socket.close
        @terminated = true

        raise ClientTerminated, "Client terminated."
      end

      def check_field_present(name)
        abort_connection "Missing field #{name.inspect}." if !@fields[name.downcase]
      end

      def check_field_present_with_value(name, value)
        check_field_present(name)

        if @fields[name.downcase] != value
          abort_connection "Invalid value of field #{name.inspect}: expected #{value.inspect}, but was #{@fields[name.downcase]}."
        end
      end

      def check_fields
        check_field_present_with_value("Upgrade",                "WebSocket")
        check_field_present_with_value("Connection",             "Upgrade")
        check_field_present_with_value("Sec-WebSocket-Protocol", "websockets-proxy")
        check_field_present("Host")
        check_field_present("Origin")
        check_field_present("Sec-WebSocket-Key1")
        check_field_present("Sec-WebSocket-Key2")
      end

      def receive_client_handshake
        # Implements steps in section 5.1.

        # Steps 1-4
        request_line = read_line
        if request_line !~ /\AGET (\/[\x21-\x7E]*) [^\r]*\r\n\z$/
          abort_connection "Invalid request line: #{request_line}."
        end
        @resource_name = $1

        # Step 5
        @fields = {}
        while (line = read_line) != "\r\n"
          if line !~ /\A([\x21-\x39\x3B-\x7E]+): (.*)\r\n\z/
            abort_connection "Invalid field line: #{line}."
          end
          @fields[$1.downcase] = $2
        end

        # Step 6
        @body = read_bytes(8)

        check_fields
      end

      def send_server_handshake
        # Implements steps in section 5.2.

        # Step 1 is not implemented -- we don't support encryption.

        # Setp 2
        host   = @fields["host"]
        origin = @fields["origin"]
        key_1  = @fields["sec-websocket-key1"]
        key_2  = @fields["sec-websocket-key2"]
        key_3  = @body

        # Step 3
        location = "ws://#{host}#{resource_name}"

        # Step 4
        key_number_1 = key_1.tr("^0-9", "").to_i
        key_number_2 = key_2.tr("^0-9", "").to_i

        # Step 5
        spaces_1 = key_1.count(" ")
        if spaces_1 == 0
          abort_connection "No spaces in the value of field \"Sec-Websocket-Key1\": #{key_1.inspect}."
        end
        spaces_2 = key_2.count(" ")
        if spaces_2 == 0
          abort_connection "No spaces in the value of field \"Sec-Websocket-Key1\": #{key_2.inspect}."
        end

        # Step 6
        if key_number_1 % spaces_1 != 0
          abort_connection "Invalid value of field \"Sec-Websocket-Key1\": #{key_1.inspect}."
        end
        if key_number_2 % spaces_2 != 0
          abort_connection "Invalid value of field \"Sec-Websocket-Key1\": #{key_2.inspect}."
        end

        # Step 7
        part_1 = key_number_1 / spaces_1
        part_2 = key_number_2 / spaces_2

        # Step 8
        challenge = [part_1, part_2].pack("NN") + key_3

        # Step 9
        response = Digest::MD5.digest(challenge)

        # Steps 10-13
        write_line "HTTP/1.1 101 WebSocket Protocol Handshake"
        write_line "Upgrade: WebSocket"
        write_line "Connection: Upgrade"
        write_line "Sec-WebSocket-Location: #{location}"
        write_line "Sec-WebSocket-Origin: #{origin}"
        write_line "Sec-WebSocket-Protocol: #{@protocol}"
        write_line ""
        write_bytes response
      end
  end

  class Proxy
    public
      def initialize(port)
        @port = port
      end

      def run
        TCPServer.open(@port) do |server_socket|
          WebSockets.info "Listening on port #{@port}..."

          loop do
            Thread.start(server_socket.accept) do |client_socket|
              Thread.current.abort_on_exception = true

              WebSockets.info "Accepted connection from #{client_socket.addr[3]}."

              web_socket = nil
              remote_socket = nil
              begin
                web_socket, proxied_host, proxied_port = initialize_web_socket(client_socket)
                break if !web_socket

                remote_socket = initialize_remote_socket(proxied_host, proxied_port)
                if !remote_socket
                  web_socket.terminate
                  break
                end

                select_loop(web_socket, remote_socket)
              rescue StandardError => e
                WebSockets.info "Error: #{e.message}"
                if web_socket && web_socket.handshaked? && !web_socket.terminated?
                  web_socket.terminate
                end
                remote_socket.close if remote_socket
              end
            end
          end
        end
      end

    private
      def initialize_web_socket(client_socket)
        web_socket = WebSocket.new(client_socket, "websockets-proxy")
        begin
          web_socket.handshake
        rescue ConnectionAborted => e
          WebSockets.info "Connection aborted: #{e.message}"
          return nil
        end

        parts = web_socket.resource_name.split(":")
        if parts.size != 2 || parts[1] !~ /^\d+$/
          web_socket.terminate
          WebSockets.info "Resource name does not contian host and port: #{web_socket.resource_name}."
          return nil
        end
        proxied_host = parts[0][1..-1]
        proxied_port = parts[1].to_i

        [web_socket, proxied_host, proxied_port]
      end

      def initialize_remote_socket(proxied_host, proxied_port)
        WebSockets.info "Connecting to #{proxied_host}:#{proxied_port}..."
        begin
          remote_socket = TCPSocket.new(proxied_host, proxied_port)
        rescue StandardError => e # We don't know what can be raised by
                                  # TCPSocket.new, so we are very unspecific
                                  # here.
          WebSockets.info "Error connecting to #{proxied_host}:#{proxied_port}: #{e.message}"
          return nil
        end
        WebSockets.info "Connected to #{proxied_host}:#{proxied_port}."

        remote_socket
      end

      def select_loop(web_socket, remote_socket)
        loop do
          sockets, = IO.select([web_socket.socket, remote_socket])

          if sockets.include?(web_socket.socket)
            begin
              data = Base64.decode64(web_socket.read_frame)
            rescue ConnectionAborted => e
              WebSockets.info "Connection aborted: #{e.message}"
              remote_socket.close
              return
            rescue ClientTerminated
              WebSockets.info "Connection terminated by client."
              remote_socket.close
              return
            end

            remote_socket.write(data)
            remote_socket.flush
            WebSockets.debug "Remote write #{data.size} bytes: #{data.inspect}"
          end

          if sockets.include?(remote_socket)
            data = nil
            begin
              data = remote_socket.readpartial(4096)
            rescue EOFError
              WebSockets.info "Connection terminated by remote."
              web_socket.terminate
              remote_socket.close
              return
            end
            WebSockets.debug "Remote read #{data.size} bytes: #{data.inspect}"

            web_socket.write_frame(Base64.encode64(data).gsub("\n", ""))
            web_socket.socket.flush
          end
        end
      end
  end
end

trap("INT") { abort "Interrupted." }

options = {
  :port    => 8080,
  :verbose => false,
  :debug   => false,
}

opts = OptionParser.new do |opts|
  opts.banner = "Usage: #$0 [--port PORT]"

  opts.separator ""
  opts.separator "Options:"

  opts.on "-p", "--port PORT", Integer, "port to listen to (default: 8080)" do |port|
    options[:port] = port
  end

  opts.on "-v", "--verbose", "enable additional output" do
    options[:verbose] = true
  end

  opts.on "-d", "--debug", "enable debug output" do
    options[:debug] = true
  end

  opts.on "-h", "--help", "print help and exit" do
    puts opts
    exit
  end

  begin
    opts.parse!(ARGV)
  rescue OptionParser::InvalidOption => e
    abort e
  rescue OptionParser::MissingArgument => e
    abort e
  end

  WebSockets.verbose = options[:verbose]
  WebSockets.debug   = options[:debug]

  WebSockets::Proxy.new(options[:port]).run
end
