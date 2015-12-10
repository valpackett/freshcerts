require 'rack/attack'
require './app'

Thread.new do
  loop do
    check_sites
  end
end

Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
Rack::Attack.throttle('req/ip', :limit => 4, :period => 1.second) do |req|
  req.ip
end

use Rack::Attack
run App
