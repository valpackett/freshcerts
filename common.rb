require 'openssl'
require 'acme-client'
require 'yaml/store'
require 'json/jwt'
require 'mail'

ACME_ENDPOINT    = ENV['ACME_ENDPOINT']    || 'https://acme-staging.api.letsencrypt.org/'
DATA_ROOT        = ENV['DATA_ROOT']        || File.join(File.dirname(__FILE__), 'data')
ADMIN_EMAIL      = ENV['ADMIN_EMAIL']      || 'root@localhost'
SMTP_ADDRESS     = ENV['SMTP_ADDRESS']     || 'localhost'
SMTP_PORT        =(ENV['SMTP_PORT']        || '25').to_i
SMTP_USERNAME    = ENV['SMTP_USERNAME']
SMTP_PASSWORD    = ENV['SMTP_PASSWORD']
SMTP_AUTH        = ENV['SMTP_AUTH']

ACCOUNT_KEY_PATH = ENV['ACCOUNT_KEY_PATH'] || File.join(DATA_ROOT, 'account.key.pem')
STORE_PATH       = ENV['STORE_PATH']       || File.join(DATA_ROOT, 'store.yaml')
TOKENS_KEY_PATH  = ENV['TOKENS_KEY_PATH']  || File.join(DATA_ROOT, 'tokens.key.pem')

CLIENT_SCRIPT    = File.read File.join File.dirname(__FILE__), 'freshcerts-client'
TOKENS_EC_CURVE  = 'prime256v1'

unless File.exist? ACCOUNT_KEY_PATH
  STDERR.puts "No account key found at #{ACCOUNT_KEY_PATH}. Create one with `openssl genrsa -out #{ACCOUNT_KEY_PATH} 4096`."
  exit 1
end

unless File.exist? TOKENS_KEY_PATH
  STDERR.puts "No tokens key found at #{TOKENS_KEY_PATH}. Create one with `openssl ecparam -genkey -name #{TOKENS_EC_CURVE} -out #{TOKENS_KEY_PATH}`."
  exit 1
end

Mail.defaults do
  delivery_method :smtp, :address => SMTP_ADDRESS, :port => SMTP_PORT, :user_name => SMTP_USERNAME, :password => SMTP_PASSWORD, :authentication => SMTP_AUTH
end

module Freshcerts
  Site = Struct.new :ports, :status, :last_checked, :cert_sha256, :expires

  class SitesProxy
    def initialize(store)
      @store = store
    end

    def transaction(read_only = false)
      @store.transaction(read_only) { yield @store }
    end

    def all
      @store.transaction(true) { Hash[@store.roots.map { |k| [k, @store[k]] }] }
    end

    def [](key)
      @store.transaction(true) { @store[key] }
    end

    def []=(key, val)
      @store.transaction { @store[key] = val }
    end
  end

  def self.sites
    @@sites_store ||= YAML::Store.new(STORE_PATH).tap do |store|
      store.ultra_safe = true
      store.instance_eval { |_| @thread_safe = true } # LOL: it's set to {} because the initializer calls super without args, and the 2nd arg has a different meaning
    end
    @@sites ||= SitesProxy.new @@sites_store
  end

  class TokenError < StandardError
  end

  class TokensProxy
    def initialize(key)
      @key = key
    end

    def generate(info)
      JSON::JWT.new(:iss => 'freshcerts', :info => info).sign(@key, :ES256).to_s
    end

    def check!(token)
      JSON::JWT.decode (token || 'WRONG'), @key
    rescue Exception => e
      raise TokenError.new(e)
    end
  end

  def self.tokens
    @@tokens ||= TokensProxy.new OpenSSL::PKey::EC.new File.read TOKENS_KEY_PATH
  end

  def self.acme
    @@acme_client ||= Acme::Client.new :private_key => OpenSSL::PKey::RSA.new(File.read(ACCOUNT_KEY_PATH)), :endpoint => ACME_ENDPOINT
  end

  def self.hash_cert(certificate)
    OpenSSL::Digest::SHA256.hexdigest(certificate.to_der).scan(/../).join(':')
  end

  def self.notify_admin(event, description)
    Mail.new {
      from "#{Etc.getlogin}@#{Socket.gethostname}"
      to ADMIN_EMAIL
      subject "freshcerts event: #{event}"
      body description
    }.deliver
  end
end
