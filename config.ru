unless ['1', 'yes', 'true', 'on'].include? (ENV['SEPARATE_MONITORING'] || '0').downcase
  require './monitoring'

  Thread.new do
    puts "Monitor thread started"
    loop do
      Freshcerts::Monitoring.check_sites
      GC.start
      sleep 5.minutes
    end
  end
end

require 'rack/attack'
require './app'

Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
Rack::Attack.throttle('req/ip', :limit => 4, :period => 1.second) { |req| req.ip }

use Rack::Attack
run Freshcerts::App
