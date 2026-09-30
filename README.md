# snacme - Minimal Python3 ACME client
Supports http-01 challenge with webroot and dns-01 challenge using the Cloudflare API.  
Supports publishing and maintaining DANE TLSA records on Cloudflare.  
This includes monthly key rotation with current and next key published over TLSA.  
Supports issuing certificates for multiple key types at once (e.g. ECC and RSA side by side).  
Supports ACME Renewal Information (ARI, [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773)) to renew certificates when the CA suggests it.

[Python cryptography](https://cryptography.io/en/latest/) is used to generate RSA-2048/3072/4096 or ECC-256/384 account and domain private keys.  
The account key is generated automatically and saved under `accounts/<base64(ACME-server-uri)>/<key-type>/account_key.pem`.  
There is one ACME account per key type.  
The default key algorithm is `ec-384`, also known as P-384 or secp384r1.  
Certificate related files are stored in `certs/<name>/<key-type>/` (e.g. `certs/name1/ec-384/`):
- privkey.pem: Currently used private key
- privkey-next.pem: Pre-generated next private key (needed for DANE TLSA)
- cert.csr: Certificate signing request
- fullchain.pem: cert.pem + chain.pem
- cert.pem: Signed certificate
- chain.pem: Intermediate certificate

These are actually symlinks to the current version of the file, which is stored as `filename-unixtime.ext` and never deleted.

The script will not regenerate certificates unless forced, the certificate has reached its ARI renewal window (or, if the CA does not support ARI, expires in less than 30 days) or the domain names for the certificate have changed in the config.

Certificates from older versions, stored directly in `certs/<name>/`, are migrated automatically to `certs/<name>/<key-type>/` on the next run.  
The key type is detected from the existing `privkey.pem`. Update any hardcoded paths that point into `certs/<name>/` accordingly.


### Multiple key types
Certificates can be issued in several key types at once, for example ECC for modern clients and RSA for legacy ones.  
A separate private key, certificate and (with dns-01 + DANE) TLSA record set is maintained for every key type.  
The key types are selected in this order of precedence:
1. `-t`/`--key-types` on the command line (one or more types, e.g. `-t ec-384 rsa-2048`)
2. `type:` inside a certificate entry in the config
3. `type:` in the root of the config
4. Default: `ec-384`

`type` in the config can be a single key type or a list.  
Valid key types: `rsa-2048`, `rsa-3072`, `rsa-4096`, `ec-256`, `ec-384`.

When issuing more than one key type for a certificate, use the `{type}` placeholder in `copy` targets and `deploy` commands, otherwise the files of the different key types overwrite each other.  
See the example config below.


### Automatic renewal (ARI)
If the ACME server advertises a `renewalInfo` endpoint, snacme asks the CA when each certificate should be renewed and renews as soon as the suggested renewal window has started.  
This allows the CA to trigger early renewals, e.g. in case of a mass revocation.  
If the server does not support ARI, snacme falls back to renewing when less than 30 days of validity are left.  
Changed domain names in the config and `--force`/`--force-one` always trigger a renewal.


### DANE TLSA
Only dns-01 over Cloudflare DNS is supported.  
Make sure you have DNSSEC enabled, otherwise DANE TLSA is kinda pointless.  
TLSA `3 1 1` records can be managed automatically over Cloudflare API, check the example config.  
There are always two TLSA records published, one for the currently used private key and the other for the next private key.  
Otherwise the service would be offline briefly after every private key change.  
Private keys are rotated after 30 days (if a new certificate is generated, so generally after 60 days).  
With multiple key types, the `dane` records from the config are shared: the current and next key of every key type are published to the same record, so it holds two TLSA entries per key type.  

The recommended setup is to only publish a single TLSA record per certificate and use CNAME.  
Example:
```
;; QUESTION SECTION:
;_443._tcp.example.com.             IN      TLSA

;; ANSWER SECTION:
_443._tcp.example.com.      300     IN      CNAME   dane1.example.com.
dane1.example.com.          300     IN      TLSA    3 1 1 1332FE5845A601D623043B1C6824C1E019A0D7DE33A4CB7308A88D89 87EF66C5
dane1.example.com.          300     IN      TLSA    3 1 1 A41BE4D4FA8D794713F08FDBD3D9A30026AB0B110A48087A16C1338F 745A1B8E
```


### Dependencies
- python3
- python3-cryptography
- python3-requests
- python3-dnspython (for dns-01 cloudflare hook)
- python3-yaml (if using .yaml config)

Debian: `apt-get install python3-cryptography python3-requests python3-dnspython python3-yaml`  
Archlinux: `pacman -S python-cryptography python-requests python-dnspython python-yaml`


### Usage
```
usage: snacme.py [-h] [-c CONFIG] [-f] [-fo name] [-fk] [-r name] [-ra] [-t type [type ...]] [--email EMAIL] [--staging] [--acme-server URL] [--ca-cert PEM] [-v]

snacme - Minimal Python3 ACME client

options:
  -h, --help            show this help message and exit
  -c, --config CONFIG   config file in JSON or YAML (.yaml or .yml) format
  -f, --force           force renew all certificates
  -fo, --force-one name
                        force renew one certificate
  -fk, --force-key      force private key rotation when renewing certificates
  -r, --revoke name     revoke one certificate
  -ra, --revoke-all     revoke all certificates
  -t, --key-types type [type ...]
                        Key types to generate. Valid choices: rsa-2048, rsa-3072, rsa-4096, ec-256, ec-384 (default: ['ec-384'])
  --email EMAIL         e-mail address used for account registration
  --staging             use Let's Encrypt staging server
  --acme-server URL     custom ACME server
  --ca-cert PEM         custom ca-cert for ACME server
  -v, --verbose         debug verbosity

```


### Config file
Default = `config.json` or `config.yaml` or `config.yml`, in this order.  
Can be either json (.json) or yaml (.yaml or .yml)
```
# type: ec-384 # default key type(s) for all certificates, string or list
certificates:
  name1:
    # type: [ec-384, rsa-2048] # key type(s) for this certificate, overrides the root setting
    domains:
      - example.com
      - www.example.com
      - a.example.com
    challenge: http-01
    http-01:
      default: /var/www/.well-known/acme-challenge
      a.example.com: /var/www/example.com/a/.well-known/acme-challenge
    copy:
      privkey: /etc/ssl/private/{name}.key
      cert: /etc/ssl/private/{name}.crt
      fullchain:
        - /etc/ssl/private/{name}.pem
        - /etc/nginx/ssl/{name}.pem
    deploy:
      - cat {privkey} {fullchain} > /home/znc/.znc/znc.pem
      - |
        sftp -oIdentityFile=~/.ssh/id_ed25519_sslsync root@remote.server <<EOF
          put {privkey} /etc/ssl/private/{name}.key
          put {fullchain} /etc/ssl/private/{name}.pem
        EOF

  name2:
    disabled: true
    domains:
      - example2.com
      - "*.example2.com"
    challenge: dns-01
    dns-01:
      # name: example2.com # CF zone name, if the domains list only has subdomains
      email: admin@example.com
      key: bfb3c49054cf3ec1e1fe101cea1f45b6
      dane:
        - dane1
    deploy: ./deploy.sh {name} {privkey} {fullchain}

  name3:
    # one certificate in two key types, {type} keeps the files apart
    type:
      - ec-384
      - rsa-2048
    domains:
      - example3.com
    challenge: http-01
    http-01:
      default: /var/www/.well-known/acme-challenge
    copy:
      privkey: /etc/ssl/private/{name}.{type}.key
      fullchain: /etc/ssl/private/{name}.{type}.pem
    deploy: ./deploy.sh {name} {type} {privkey} {fullchain}

alldone:
  - systemctl reload nginx
  - systemctl restart vsftpd
```

Custom ACME server URI can be specified in the root of the config: `acme_server: 'uri'`

Placeholders available in `copy` targets and `deploy` commands:
- `{name}`: certificate name
- `{type}`: key type being processed, e.g. `ec-384`
- `{privkey}`, `{fullchain}`, `{cert}`, `{chain}`: paths to the current files (`deploy` only)

`copy` and `deploy` run once per key type, after each successful issuance.  
`alldone` runs once at the end if at least one certificate was issued.


### systemd example
`/etc/systemd/system/snacme.timer`
```
[Unit]
Description=Run snacme cronjob every day.

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

`/etc/systemd/system/snacme.service`
```
[Unit]
Description=Run snacme cronjob

[Service]
Type=simple
Restart=on-failure
User=root
WorkingDirectory=/root/snacme
ExecStart=/root/snacme/snacme.py
```


### nginx http-01 example
`/etc/nginx/conf.d/default.conf`
```
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name _;

  location /.well-known/acme-challenge {
    root /var/www;
  }

  location / {
    return 301 https://$host$request_uri;
  }
}
```
