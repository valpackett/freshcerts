require 'openssl'
require 'active_support/time'
require './common'

module Freshcerts::Monitoring
  def self.check_site(domain, port, wanted_hash)
    OpenSSL::SSL::SSLSocket.new(TCPSocket.new domain, port).tap do |sock|
      sock.hostname = domain
      sock.sync_close = true
      sock.connect
      found_hash = Freshcerts.hash_cert sock.peer_cert
      yield (wanted_hash == found_hash ? :ok : :wrong_cert), found_hash
      sock.close
    end
  end

  def self.check_sites
    Freshcerts.sites.all.each do |domain, site|
      site.ports.each do |port|
        begin
          puts "Checking #{domain}:#{port}"
          wanted_hash = site.cert_sha256
          check_site(domain, port, wanted_hash) do |status, found_hash|
            if status == :wrong_cert
              Freshcerts.notify_admin "monitoring found cert error for #{domain}:#{port}",
                "Found a certificate with SHA-256 figerprint\n\n#{found_hash}\n\n, should be\n\n#{wanted_hash}."
              puts "#{domain}:#{port} wrong cert: #{found_hash}, should be #{wanted_hash}"
            else
              puts "#{domain}:#{port} ok"
            end
            site.status = status
          end
        rescue => e
          Freshcerts.notify_admin "monitoring could not connect to #{domain}:#{port}",
            "Could not connect to #{domain}:#{port}.\n\nException: #{e.class}: #{e.message}\nBacktrace:\n#{e.backtrace.join "\n"}"
          puts "#{domain}:#{port} exception: #{e}"
          site.status = :conn_error
        end
        site.last_checked = Time.now
        Freshcerts.sites[domain] = site
        sleep 2.seconds
      end
    end
    sleep 5.minutes
  end
end
