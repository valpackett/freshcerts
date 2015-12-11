require 'sinatra/base'
require 'sinatra/streaming' # IO object compatibility
require 'tilt/erubis'
require 'active_support/time'
require 'openssl'
require 'rubygems/package'
require './common'

$challenges = {}

class App < Sinatra::Base
  helpers Sinatra::Streaming
  configure :production, :development do
    enable :logging
  end

  get '/.well-known/acme-challenge/:id' do
    $challenges[params[:id]]
  end

  get '/v1/cert/:domain/should_reissue' do
    site = $store.transaction(true) do
      $store[params[:domain]]
    end
    halt 200, "Reissue reason: No certs for domain #{params[:domain]} have been issued yet!\n" if site.nil?
    halt 200, "Reissue reason: Cert expires sooner than 10 days!\n" if Time.now > site.expires - 10.days
    halt 200, "Reissue reason: Wrong cert is used!\n" if site.status == :wrong_cert
    halt 200, "Reissue reason: Colud not connect!\n" if site.status == :conn_error
    halt 400, "Everything is OK, no reissue required.\n"
  end

  post '/v1/cert/:domain/issue' do
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
    sha256hash = hash_cert certificate
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

  get '/robots.txt' do
    "User-agent: *\nDisallow: /"
  end

  get '/humans.txt' do
    'freshcerts <https://github.com/myfreeweb/freshcerts> is created by Greg <https://unrelenting.technology>'
  end

  get '/' do
    domains = $store.transaction(true) do
      Hash[$store.roots.map { |k| [k, $store[k]] }]
    end
    headers "Refresh" => "30"
    erb :index, :locals => {
      :domains => domains,
      :config_host => request.host,
      :config_port => request.port,
      :config_secure => request.secure?,
      :client_script => CLIENT_SCRIPT
    }
  end
end
