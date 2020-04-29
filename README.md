# snacme - Minimal Python3 ACME client
Supports http-01 challenge with webroot and dns-01 challenge using the Cloudflare API.

[Python cryptography](https://cryptography.io/en/latest/) is used to generate RSA-2048/4096 or ECC-256/384 account and domain private keys.  
The account key is generated automatically and saved under `accounts/<base64(ACME-server-uri)>/<key-type>/account_key.pem`.  
The default key algorithm is `ec-384`, also known as P-384 or secp384r1.  
Domain related files are stored in `certs/<name>/`:
- privkey.pem: Domain private key, new one generated for every certificate.
- cert.csr: Certificate signing request
- fullchain.pem: cert.pem + chain.pem
- cert.pem: Signed certificate
- chain.pem: Intermediate certificate

These are actually symlinks to the latest version of the file, which is stored as `filename-unixtime.ext` and never deleted.

The script will not regenerate certificates unless forced or a certificate expires in less than 30 days or the domain names for the certificate have changed in the config.

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
usage: snacme.py [-h] [-c CONFIG] [-f] [-fo name] [-r name] [-ra] [-t type]
                 [--email EMAIL] [--staging] [--acme-server URL] [--ca-cert PEM] [-v]

snacme - Minimal Python3 ACME client

optional arguments:
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        config file in JSON or YAML (.yaml or .yml) format
  -f, --force           force renew all certificates
  -fo name, --force-one name
                        force renew one certificate
  -r name, --revoke name
                        revoke one certificate
  -ra, --revoke-all     revoke all certificates
  -t type, --key-type type
                        Key type to generate. Valid choices: rsa-2048, rsa-4096, ec-256,
                        ec-384 (default: ec-384)
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
domains:
  name1:
    domains:
      - example.com
      - www.example.com
      - a.example.com
    challenge: http-01
    http-01:
      default: /var/www/example.com/htdocs/.well-known/acme-challenge
      a.example.com: /var/www/example.com/a/.well-known/acme-challenge
    copy:
      privkey: /etc/ssl/private/{name}.key
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
      # name: example2.com # if the domains list only has subdomains
      email: admin@example.com
      key: bfb3c49054cf3ec1e1fe101cea1f45b6
    deploy: ./deploy.sh {name} {privkey} {fullchain}

alldone:
  - systemctl reload nginx
  - systemctl restart vsftpd
```
