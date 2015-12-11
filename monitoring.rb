require 'openssl'
require 'active_support/time'
require './common'

def check_sites
  $store.transaction do
    $store.roots.each do |domain|
      site = $store[domain]
      site.ports.each do |port|
        begin
          puts "Checking #{domain}:#{port}"
          OpenSSL::SSL::SSLSocket.new(TCPSocket.new(domain, port)).tap do |sock|
            sock.sync_close = true
            sock.connect
            cert_sha256 = hash_cert(sock.peer_cert)
            site.last_checked = Time.now
            site.status = site.cert_sha256 == cert_sha256 ? :ok : :wrong_cert
            if site.status == :wrong_cert
              puts "#{domain}:#{port} wrong cert: #{cert_sha256}, should be #{site.cert_sha256}"
            else
              puts "#{domain}:#{port} ok"
            end
            sock.close
          end
        rescue Exception => e
          puts "#{domain}:#{port} exception"
          p e
          site.status = :conn_error
        end
        sleep 2.seconds
      end
    end
  end
  sleep 5.minutes
end
