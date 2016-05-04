require 'sinatra/base'
require 'sinatra/streaming' # IO object compatibility
require 'tilt/erubis'
require 'active_support/time'
require 'openssl'
require 'domain_name'
require 'thread_safe'
require 'rubygems/package'
require './common'

$challenges = ThreadSafe::Cache.new

class Freshcerts::App < Sinatra::Base
  class DomainError < StandardError
  end

  def domain
    d = params[:domain]
    raise DomainError if d.nil? || d.include?(' ')
    @domain ||= DomainName(d).hostname
  end

  def issue_error!(msg)
    Freshcerts.notify_admin 'certificate issue error', "Error message:\n#{msg}\n\nRequest:\n#{request.to_yaml}"
    halt 400, msg
  end

  error OpenSSL::X509::RequestError do
    issue_error! 'Could not read the CSR. You should send a valid CSR as a multipart part named "csr".'
  end

  error DomainError do
    issue_error! "Domain '#{domain}' is not valid."
  end

  error Freshcerts::TokenError do
    issue_error! 'A valid authentication token was not provided.'
  end

  error Acme::Client::Error::Malformed do
    issue_error! "Domain '#{domain}' is not supported by the CA."
  end

  helpers Sinatra::Streaming
  configure :production, :development do
    enable :logging
    disable :show_exceptions
  end

  get '/.well-known/acme-challenge/:id' do
    content_type 'text/plain'
    $challenges[params[:id]]
  end

  get '/v1/cert/:domain/should_reissue' do
    site = Freshcerts.sites[domain]
    halt 200, "Reissue reason: No certs for domain #{domain} have been issued yet!\n" if site.nil?
    halt 200, "Reissue reason: Cert expires sooner than 10 days!\n" if Time.now > site.expires - 10.days
    halt 200, "Reissue reason: Wrong cert is used!\n" if site.status == :wrong_cert
    halt 200, "Reissue reason: Colud not connect!\n" if site.status == :conn_error
    halt 400, "Everything is OK, no reissue required.\n"
  end

  post '/v1/cert/:domain/issue' do
    Freshcerts.tokens.check! params[:token]
    challenge = make_challenge
    verify_challenge challenge
    issue
  end

  def make_challenge
    authorization = Freshcerts.acme.authorize :domain => domain
    challenge = authorization.http01
    challenge_id = challenge.filename.sub /.*challenge\/?/, ''
    $challenges[challenge_id] = challenge.file_content
    logger.info "make_challenge domain=#{domain} id=#{challenge_id}"
    challenge
  end

  def verify_challenge(challenge)
    sleep 0.1
    challenge.request_verification
    status = nil
    while (status = challenge.verify_status) == 'pending'
      sleep 0.5
    end
    challenge_id = challenge.filename.sub /.*challenge\/?/, ''
    logger.info "verify_challenge domain=#{domain} id=#{challenge_id} status=#{status}"
    unless status == 'valid'
      $challenges.delete challenge_id
      issue_error! "CA returned challenge validation status: #{status}.\n\nChallenge:\n#{challenge.to_yaml}"
    end
    $challenges.delete challenge_id
  end

  def issue
    csr = OpenSSL::X509::Request.new params[:csr][:tempfile].read
    ports = (params[:ports] || '443').split(',').map { |port| port.strip.to_i }
    certificate = Freshcerts.acme.new_certificate csr
    cert_hash = Freshcerts.hash_cert certificate
    logger.info "issue domain=#{domain} subject=#{certificate.x509.subject.to_s} sha256=#{cert_hash} expires=#{certificate.x509.not_after.to_s}"
    Freshcerts.sites[domain] = Freshcerts::Site.new ports, :fresh, Time.now, cert_hash, certificate.x509.not_after
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
    Freshcerts.notify_admin "successfully issued a certificate for #{domain}",
      "Successfully issued a certificate for domain #{domain}!\nSHA-256 fingerprint: #{cert_hash}.\n\nRequest:\n#{request.to_yaml}"
  end

  get '/robots.txt' do
    "User-agent: *\nDisallow: /"
  end

  get '/humans.txt' do
    'freshcerts <https://github.com/myfreeweb/freshcerts> is created by Greg <https://unrelenting.technology>'
  end

  get '/' do
    headers "Refresh" => "30"
    erb :index, :locals => {
      :domains => Freshcerts.sites.all,
      :config_host => request.host,
      :config_port => request.port,
      :config_secure => request.secure?,
      :client_script => CLIENT_SCRIPT
    }
  end
end
