# freshcerts [![unlicense](https://img.shields.io/badge/un-license-green.svg?style=flat)](http://unlicense.org)

![Screenshot](https://files.app.net/h02q76bXk.png)

[ACME](https://letsencrypt.github.io/acme-spec/) (currently implemented by [Let's Encrypt](https://letsencrypt.org)) is a way to automatically (re)issue TLS certificates.

Most ACME clients are designed to run on the same machine as your TLS services. 
But if you have a lot of servers, there are two problems with that:
- you either have to copy your account private key onto all of them, or register multiple accounts;
- you don't have a nice monitoring dashboard & notifications!

freshcerts solves both problems.
It runs a server that exposes a much simpler API to your servers (they'll use a tiny shell script that's pretty much `openssl | curl | tar`) and a dashboard to your system administrators.
Servers are monitored to ensure they actually use the certs issued for them.
Email notifications are sent to the admins for all errors found by monitoring and for all issued certificates.

## Installation

It's a typical Ruby app, so you'll need [Bundler](http://bundler.io):

```bash
$ git clone https://github.com/myfreeweb/freshcerts.git
$ cd freshcerts
$ bundle install --path vendor/bundle
$ mkdir data
```

Use environment variables to configure the app. Read `common.rb` to see which variables are available.
You probably should change the ACME endpoint (by default, Let's Encrypt **staging** is used, not production):

```bash
$ export ACME_ENDPOINT="https://acme-v01.api.letsencrypt.org/"
$ export ADMIN_EMAIL="support@example.com"
```

Generate a tokens key:

```bash
$ openssl ecparam -genkey -name prime256v1 -out data/tokens.key.pem
```

Generate and register an account key:

```bash
$ openssl genrsa -out data/account.key.pem 4096
$ chmod 0400 data/account.key.pem
$ bundle exec ./register-account-key
```

Run:

```bash
$ bundle exec rackup -p 9393
```

In production, you'll want to configure your process manager to run it.
Set `RACK_ENV=production` there in addition to the config variables (`ACME_ENDPOINT`, etc.)

## Usage

For every domain:

Generate an auth token with `bundle exec ./generate-token`.

Configure the HTTP server to forward `/.well-known/acme-challenge/*` requests to the freshcerts server.

Configure cron to run the `freshcerts-client` script every day.

Args: domain, subject, ports (comma separated), reload command, auth token. Like this:

```
FRESHCERTS_HOST="https://certs.example.com:4333" freshcerts-client example.com /CN=example.com 443 "service nginx reload" "eyJ0eXAiOi..."
```

Figure out cert paths and file permissions :-)

## Contributing

Please feel free to submit pull requests!

By participating in this project you agree to follow the [Contributor Code of Conduct](http://contributor-covenant.org/version/1/2/0/).

[The list of contributors is available on GitHub](https://github.com/myfreeweb/freshcerts/graphs/contributors).

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](http://unlicense.org).
