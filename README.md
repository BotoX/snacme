# snacme - Minimal Python3 ACME client
Supports http-01 challenge with webroot and dns-01 challenge using the Cloudflare API.  
Supports publishing and maintaining DANE TLSA records on Cloudflare.  
This includes monthly key rotation with current and next key published over TLSA.

[Python cryptography](https://cryptography.io/en/latest/) is used to generate RSA-2048/4096 or ECC-256/384 account and domain private keys.  
The account key is generated automatically and saved under `accounts/<base64(ACME-server-uri)>/<key-type>/account_key.pem`.  
The default key algorithm is `ec-384`, also known as P-384 or secp384r1.  
Certificate related files are stored in `certs/<name>/`:
- privkey.pem: Currently used private key
- privkey-next.pem: Pre-generated next private key (needed for DANE TLSA)
- cert.csr: Certificate signing request
- fullchain.pem: cert.pem + chain.pem
- cert.pem: Signed certificate
- chain.pem: Intermediate certificate

These are actually symlinks to the current version of the file, which is stored as `filename-unixtime.ext` and never deleted.

The script will not regenerate certificates unless forced, a certificate expires in less than 60 days or the domain names for the certificate have changed in the config.


### DANE TLSA
Only dns-01 over Cloudflare DNS is supported.  
Make sure you have DNSSEC enabled, otherwise DANE TLSA is kinda pointless.  
TLSA `3 1 1` records can be managed automatically over Cloudflare API, check the example config.  
There are always two TLSA records published, one for the currently used private key and the other for the next private key.  
Otherwise the service would be offline briefly after every private key change.  
Private keys are rotated after 30 days (if a new certificate is generated, so generally after 60 days).  

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
usage: snacme.py [-h] [-c CONFIG] [-f] [-fo name] [-fk] [-r name] [-ra] [-t type] [--email EMAIL] [--staging] [--acme-server URL] [--ca-cert PEM] [-v]

snacme - Minimal Python3 ACME client

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file in JSON or YAML (.yaml or .yml) format
  -f, --force           force renew all certificates
  -fo name, --force-one name
                        force renew one certificate
  -fk, --force-key      force private key rotation when renewing certificates
  -r name, --revoke name
                        revoke one certificate
  -ra, --revoke-all     revoke all certificates
  -t type, --key-type type
                        Key type to generate. Valid choices: rsa-2048, rsa-4096, ec-256, ec-384 (default: ec-384)
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
certificates:
  name1:
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

alldone:
  - systemctl reload nginx
  - systemctl restart vsftpd
```


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
