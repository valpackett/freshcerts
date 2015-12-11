require 'openssl'
require 'acme-client'
require 'yaml/store'

ACME_ENDPOINT    = ENV['ACME_ENDPOINT']    || 'https://acme-staging.api.letsencrypt.org/'
DATA_ROOT        = ENV['DATA_ROOT']        || File.join(File.dirname(__FILE__), 'data')
ACCOUNT_KEY_PATH = ENV['ACCOUNT_KEY_PATH'] || File.join(DATA_ROOT, 'account.key.pem')
STORE_PATH       = ENV['STORE_PATH']       || File.join(DATA_ROOT, 'store.yaml')

CLIENT_SCRIPT    = File.read File.join File.dirname(__FILE__), 'freshcerts-client'

unless File.exist? ACCOUNT_KEY_PATH
  STDERR.puts "No account key found at #{ACCOUNT_KEY_PATH}. Create one with `openssl genrsa -out #{ACCOUNT_KEY_PATH} 4096`."
  exit 1
end
pkey = OpenSSL::PKey::RSA.new File.read ACCOUNT_KEY_PATH
$acme_client = Acme::Client.new :private_key => pkey, :endpoint => ACME_ENDPOINT

$store = YAML::Store.new STORE_PATH
$store.ultra_safe = true
$store.instance_eval { |_| @thread_safe = true } # LOL: it's set to {} because the initializer calls super without args, and the 2nd arg has a different meaning

Site = Struct.new :ports, :status, :last_checked, :cert_sha256, :expires

def hash_cert(certificate)
  OpenSSL::Digest::SHA256.hexdigest(certificate.to_der).scan(/../).join(':')
end
