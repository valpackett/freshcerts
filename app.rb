require 'sinatra/base'
require 'sinatra/streaming' # IO object compatibility
require 'openssl'
require 'acme-client'
require 'yaml/store'
require 'rubygems/package'

ACME_ENDPOINT    = ENV['ACME_ENDPOINT']    || 'https://acme-staging.api.letsencrypt.org/'
DATA_ROOT        = ENV['DATA_ROOT']        || File.join(File.dirname(__FILE__), 'data')
ACCOUNT_KEY_PATH = ENV['ACCOUNT_KEY_PATH'] || File.join(DATA_ROOT, 'account.key.pem')
STORE_PATH       = ENV['STORE_PATH']       || File.join(DATA_ROOT, 'store.yaml')

unless File.exist? ACCOUNT_KEY_PATH
  STDERR.puts "No account key found at #{ACCOUNT_KEY_PATH}. Create one with `openssl genrsa -out #{ACCOUNT_KEY_PATH} 4096`."
  exit 1
end
pkey = OpenSSL::PKey::RSA.new File.read ACCOUNT_KEY_PATH
$acme_client = Acme::Client.new :private_key => pkey, :endpoint => ACME_ENDPOINT

$store = YAML::Store.new STORE_PATH
$store.ultra_safe = true
$store.instance_eval { |_| @thread_safe = true } # LOL: it's set to {} because the initializer calls super without args, and the 2nd arg has a different meaning

$challenges = {}

Site = Struct.new :ports, :status, :last_checked, :public_key_sha256, :expires

class App < Sinatra::Base
  helpers Sinatra::Streaming
  configure :production, :development do
    enable :logging
  end

  get '/.well-known/acme-challenge/:id' do
    $challenges[params[:id]]
  end

  post '/v1/cert' do
    begin
      csr = OpenSSL::X509::Request.new params[:csr][:tempfile].read
    rescue
      halt 400, 'Could not read the CSR. You should send a valid CSR as a multipart part named "csr".'
    end
    domain = params[:domain]
    unless !domain.nil? && domain =~ /(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}\.?$)/
      halt 400, "Domain '#{domain}' is not valid."
    end
    ports = (params[:ports] || '443').split(',').map { |port| port.strip.to_i }

    authorization = $acme_client.authorize :domain => domain
    challenge = authorization.http01
    challenge_id = challenge.filename.sub(/.*challenge\/?/, '')
    $challenges[challenge_id] = challenge.file_content
    logger.info "challenge domain=#{domain} id=#{challenge_id}"
    sleep 0.1
    challenge.request_verification
    status = nil
    while (status = challenge.verify_status) == 'pending'
      sleep 0.5
    end
    logger.info "challenge domain=#{domain} id=#{challenge_id} status=#{status}"
    unless status == 'valid'
      $challenges.delete challenge_id
      halt 400, "CA returned challenge validation status: #{status}."
    end
    $challenges.delete challenge_id

    certificate = $acme_client.new_certificate(csr)
    sha256hash = OpenSSL::Digest::SHA256.hexdigest(certificate.to_der).scan(/../).join(':')
    logger.info "certificate domain=#{domain} subject=#{certificate.x509.subject.to_s} sha256=#{sha256hash} expires=#{certificate.x509.not_after.to_s}"
    $store.transaction do
      $store[domain] = Site.new ports, :fresh, Time.now, sha256hash, certificate.x509.not_after
    end
    content_type 'application/x-tar'
    stream do |out|
      Gem::Package::TarWriter.new(out) do |tar|
        cert = certificate.to_pem
        tar.add_file_simple("#{domain}.cert.pem", 0444, cert.length) { |io| io.write(cert) }
        chain = certificate.chain_to_pem
        tar.add_file_simple("#{domain}.cert.chain.pem", 0444, chain.length) { |io| io.write(chain) }
        fullchain = certificate.fullchain_to_pem
        tar.add_file_simple("#{domain}.cert.fullchain.pem", 0444, fullchain.length) { |io| io.write(fullchain) }
      end
      out.flush
    end
  end

  get '/' do
    'Hello world!'
  end
end
