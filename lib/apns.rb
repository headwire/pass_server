require 'singleton'
#require 'socket'
require 'openssl'

class APNS
  include Singleton
  attr_accessor :config, :certificate, :socket, :ssl_socket

  @@certificate_password = nil

  def self.certificate_password=(password)
    @@certificate_password = password
  end

  def get_certificate_path
    certDirectory = File.dirname(File.expand_path(__FILE__)) + "/../data/Certificate"
    certs = Dir.glob("#{certDirectory}/*.p12")
    if  certs.count ==0
        puts "Couldn't find a certificate at #{certDirectory}"
        puts "Exiting"
        Process.exit
    else
        certificate_path = certs[0]
    end
  end

  def initialize
    @@certificate_password ||= get_certificate_password
    self.certificate = load_certificate(get_certificate_path, @@certificate_password)
  end

  def get_certificate_password
    #puts "Please enter your certificate password: "
    #password_input = gets.chomp
    password_input = "CegthCathjbl"

    return password_input
  end

  def load_certificate(path, password=nil)
    puts "Loading push certificate."
    context = OpenSSL::SSL::SSLContext.new
    context.verify_mode = OpenSSL::SSL::VERIFY_NONE

    # Import the certificate
    p12_certificate = OpenSSL::PKCS12::new(File.read(path), password || @@certificate_password)

    context.cert = p12_certificate.certificate
    context.key = p12_certificate.key

    # Return ssl certificate context
    return context
  end

  def open_connection(environment='production') #sandbox ? production
    if self.certificate.class != OpenSSL::SSL::SSLContext
      load_certificate
    end

    if environment == "production"
      self.socket = TCPSocket.new("gateway.push.apple.com", 2195)
    else
      self.socket = TCPSocket.new("gateway.sandbox.push.apple.com", 2195)
    end
    self.ssl_socket = OpenSSL::SSL::SSLSocket.new(APNS.instance.socket, APNS.instance.certificate)

    # Open the SSL connection
    self.ssl_socket.connect


  end

  def close_connection
    APNS.instance.ssl_socket.close
    APNS.instance.socket.close
  end

  def deliver(token, payload)
    notification_packet = self.generate_notification_packet(token, payload)
    APNS.instance.ssl_socket.write(notification_packet)
  end

  def generate_notification_packet(token, payload)
    device_token_binary = [token.delete(' ')].pack('H*')

    packet =  [
                0,
                device_token_binary.size / 256,
                device_token_binary.size % 256,
                device_token_binary,
                payload.size / 256,
                payload.size % 256,
                payload
              ]
    packet.pack("ccca*cca*")
  end


end


