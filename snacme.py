#!/usr/bin/env python3
import os
import sys
import re
import time
import datetime
import logging
import argparse
import base64
import math
import hashlib
import urllib.parse
import requests
import json
import textwrap
import contextlib
import socket
import shutil
import subprocess
try:
	import yaml
except ImportError:
	yaml = None
try:
	import dns.resolver
except ImportError:
	dns = None

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

LE_ACME_SERVER = 'https://acme-v02.api.letsencrypt.org'
LE_STAGING_ACME_SERVER = 'https://acme-staging-v02.api.letsencrypt.org'
ACME_SERVER = LE_ACME_SERVER
RENEW_DAYS = 30
CA_CERT = None

def _progress(prefix, val, end, postfix='', abort=False):
	sys.stderr.write(' ' * _progress.lastlen + '\r')
	line = '{0} {1}/{2} {3}\r'.format(prefix, val, end, postfix)
	_progress.lastlen = len(line)
	sys.stderr.write(line)
	if val == end or abort:
		sys.stderr.write('\n')
	sys.stderr.flush()
_progress.lastlen = 0

def _itery(x):
	if x is None:
		return ()
	if isinstance(x, list):
		return x
	return (x,)

def __os_removef(*args, **kwargs):
	with contextlib.suppress(FileNotFoundError):
		os.remove(*args, **kwargs)
os.removef = __os_removef

def generate_rsa_key(bits=4096):
	pkey = rsa.generate_private_key(
		public_exponent=65537,
		key_size=bits,
		backend=default_backend()
	)
	pem = pkey.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)
	return pkey, pem

def acme_b64encode(data):
	if isinstance(data, bytes):
		return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')
	else:
		return base64.urlsafe_b64encode(data.encode('utf8')).decode('ascii').rstrip('=')

class ACMEClient():
	def __init__(self, ca_url, email=None):
		self.ca_url = ca_url
		self.email = email

		r = self.api_get(urllib.parse.urljoin(self.ca_url, 'directory'))
		if not r.ok:
			raise ValueError('ACME error while getting directory: ({0})\n{1}'.format(r.status_code, r.text))
		self.directory = r.json()

		self.kid = None
		self.privkey = None
		self.pubkey = None
		self.acme_register()

	def acme_nonce(self):
		r = self.api_get(self.directory['newNonce'])
		if not r.ok:
			raise ValueError('ACME error while requesting new nonce: ({0})\n{1}'.format(r.status_code, r.text))
		nonce = r.headers['Replay-Nonce']
		return nonce

	def acme_register(self):
		accpath = os.path.join('accounts', acme_b64encode(self.ca_url + '/directory'))
		if not os.path.isdir(accpath):
			os.makedirs(accpath, mode=0o700)

		acckey = os.path.join(accpath, 'account_key.pem')
		if os.path.isfile(acckey):
			logging.debug('# Using existing account private key: %s', acckey)
			with open(acckey, 'rb') as fp:
				self.privkey = serialization.load_pem_private_key(
					fp.read(),
					password=None,
					backend=default_backend()
				)
		else:
			logging.info('# Generating new account private key...')
			self.privkey, pem = generate_rsa_key()
			with open(os.open(acckey, os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as fp:
				fp.write(pem)
		self.pubkey = self.privkey.public_key()

		reginfo = os.path.join(accpath, 'registration_info.json')
		if os.path.isfile(reginfo):
			logging.info('# Using existing account: %s', reginfo)
			with open(reginfo, 'r') as fp:
				account = json.load(fp)
		else:
			logging.info('# Registering new account on %s', self.ca_url)

			req = {
				'termsOfServiceAgreed': True
			}
			if self.email:
				req['contact'] = ['mailto:' + self.email]

			r = self.api_post(self.directory['newAccount'], json.dumps(req))
			if not r.ok:
				abort = True
				if r.status_code == 409 and r.headers['Content-Type'] == 'application/problem+json':
					try:
						err = r.json()
						if err['detail'] == 'Registration key is already in use':
							logging.info(' + Already registered.')
							abort = False
					except Exception:
						pass
				if abort:
					raise ValueError('ACME error while registering account: ({0})\n{1}'.format(r.status_code, r.text))

			account = r.json()
			account['kid'] = r.headers['Location']
			with open(reginfo, 'w') as fp:
				json.dump(account, fp)
			logging.info(' + Success!')

		self.kid = account['kid']

	def acme_order(self, domains):
		req = {
			'identifiers': [
				{
					'type': 'dns',
					'value': domain
				} for domain in domains
			]
		}
		r = self.api_post(self.directory['newOrder'], json.dumps(req))
		if not r.ok:
			raise ValueError('ACME error while creating order: ({0})\n{1}'.format(r.status_code, r.text))

		resp = r.json()
		return resp

	def acme_get_challenge(self, url):
		r = self.api_get(url)
		if not r.ok:
			raise ValueError('ACME error while getting challenge: ({0})\n{1}'.format(r.status_code, r.text))

		# calculate keyauth right away, because why not
		jwk_thumb = self.jwk_thumbprint()
		resp = r.json()
		for cha in resp['challenges']:
			cha['keyauth'] = '{0}.{1}'.format(cha['token'], jwk_thumb)

		return resp

	def acme_notify(self, url, authorization):
		req = {
			'keyAuthorization': authorization
		}
		r = self.api_post(url, json.dumps(req))
		if not r.ok:
			raise ValueError('ACME error while notifying: ({0})\n{1}'.format(r.status_code, r.text))
		return r.json()

	def acme_check_challenge(self, url):
		r = self.api_get(url)
		if not r.ok:
			raise ValueError('ACME error while checking challenge: ({0})\n{1}'.format(r.status_code, r.text))
		return r.json()

	def acme_finalize(self, url, csr):
		req = {
			'csr': acme_b64encode(csr)
		}
		r = self.api_post(url, json.dumps(req))
		if not r.ok:
			raise ValueError('ACME error while finalizing order: ({0})\n{1}'.format(r.status_code, r.text))
		return r.json()

	def acme_download_cert(self, url):
		r = self.api_get(url)
		if not r.ok:
			raise ValueError('ACME error while downloading certificate: ({0})\n{1}'.format(r.status_code, r.text))
		return r

	def acme_revoke(self, der):
		req = {
			'certificate': acme_b64encode(der)
		}
		r = self.api_post(self.directory['revokeCert'], json.dumps(req))
		if not r.ok:
			raise ValueError('ACME error while revoking certificate: ({0})\n{1}'.format(r.status_code, r.text))

	def crypto_sign_msg(self, msg):
		return self.privkey.sign(
			msg,
			padding.PKCS1v15(),
			hashes.SHA256()
		)

	def jwk(self):
		pubnums = self.pubkey.public_numbers()
		return {
			'e': acme_b64encode(pubnums.e.to_bytes(math.ceil(pubnums.e.bit_length() / 8), 'big')),
			'kty': 'RSA',
			'n': acme_b64encode(pubnums.n.to_bytes(self.pubkey.key_size // 8, 'big'))
		}

	def jws_header(self):
		res = {'alg': 'RS256'}
		if self.kid:
			res['kid'] = self.kid
		else:
			res['jwk'] = self.jwk()
		return res

	def jws_sign(self, url, payload):
		payload = acme_b64encode(payload)
		protected = self.jws_header()
		protected['nonce'] = self.acme_nonce()
		protected['url'] = url
		protected = acme_b64encode(json.dumps(protected))
		signature = '{0}.{1}'.format(protected, payload).encode('utf8')
		signature = self.crypto_sign_msg(signature)
		signature = acme_b64encode(signature)

		return json.dumps({
			'protected': protected,
			'payload': payload,
			'signature': signature
		}).encode('utf8')

	def jwk_thumbprint(self):
		jwk = self.jwk()
		jwk = json.dumps(jwk, sort_keys=True, separators=(',', ':'))
		return acme_b64encode(hashlib.sha256(jwk.encode('utf8')).digest())

	def _requests_request(self, method, url, data=None, headers={}):
		_headers = {'User-Agent': 'snacme/dev'}
		_headers.update(headers)
		try:
			r = requests.request(method=method, headers=_headers, url=url, data=data, timeout=5, verify=CA_CERT)
		except Exception as e:
			raise e
		return r

	def api_get(self, url):
		return self._requests_request('GET', url)

	def api_post(self, url, payload):
		headers = {'Content-Type': 'application/jose+json'}
		data = self.jws_sign(url, payload)
		return self._requests_request('POST', url, data, headers)


class HTTP01Challenger():
	def __init__(self, config, domains):
		self.config = config
		self.domains = domains
		self.needclean = []

	def deploy(self, chalist):
		for cha in chalist:
			domain = cha['identifier']['value']
			mycha = next((i for i in cha['challenges'] if i['type'] == 'http-01'), None)

			wellknown = self.config.get('default', None)
			if domain in self.config:
				wellknown = self.config[domain]
			if not wellknown:
				logging.error('! No well-known path for %s', domain)
				return False
			if not os.path.isdir(wellknown):
				os.makedirs(wellknown)

			path = os.path.normpath(os.path.join(wellknown, mycha['token']))
			if not path.startswith(wellknown):
				logging.info(' ! Someone is trying to hack us: %s', mycha['token'])
				return False
			logging.info(' + Writing well-known for %s to: %s', domain, path)
			with open(path, 'wb') as fd:
				fd.write(mycha['keyauth'].encode('ascii'))
			self.needclean.append(path)
		return True

	def clean(self):
		logging.info('# Challenge cleanup.')
		for path in self.needclean:
			os.remove(path)

class DNS01CloudflareChallenger():
	def __init__(self, config, domains):
		self.config = config
		self.domains = domains
		self.needclean = []
		self.headers = {
			'Content-Type': 'application/json',
			'X-Auth-Email': self.config['email'],
			'X-Auth-Key': self.config['key']
		}

		self.domain = min(self.domains, key=len)
		if 'domain' in self.config:
			self.domain = self.config['domain']
		r = requests.get('https://api.cloudflare.com/client/v4/zones?name={0}'.format(self.domain), headers=self.headers)
		if not r.ok:
			raise ValueError('Cloudflare API error while getting zone: ({0})\n{1}'.format(r.status_code, r.text))
		self.zone = r.json()['result'][0]['id']

	def deploy(self, chalist):
		pending = []
		url = 'https://api.cloudflare.com/client/v4/zones/{0}/dns_records'.format(self.zone)
		soll = len(chalist) - 1
		for ist, cha in enumerate(chalist):
			domain = cha['identifier']['value']
			mycha = next((i for i in cha['challenges'] if i['type'] == 'dns-01'), None)

			_progress(' + Writing DNS record', ist, soll, domain)
			name = "_acme-challenge.{0}".format(domain)
			txt = acme_b64encode(hashlib.sha256(mycha['keyauth'].encode('ascii')).digest())
			data = json.dumps({
				"type": "TXT",
				"name": name,
				"content": "{0}".format(txt),
				"ttl": 1
			})
			r = requests.post(url, data=data, headers=self.headers)
			if not r.ok:
				logging.error(' ! Cloudflare API error while writing record: ({0})\n{1}'.format(r.status_code, r.text))
				return False
			self.needclean.append(r.json()['result']['id'])
			pending.append((name, txt))

		logging.info('# Waiting for DNS to propagate...')
		if not dns:
			logging.warning(' ! dnspython not installed, waiting for 30 seconds instead.')
			for i in range(1, 31):
				_progress(' + Waiting...', i, 30)
				time.sleep(1)
			return True

		dns_servers = dns.resolver.query(self.domain, 'NS')
		dns_servers = [i.to_text() for i in dns_servers]
		dns_servers = [socket.gethostbyname(i) for i in dns_servers]
		resolver = dns.resolver.Resolver()
		resolver.nameservers = dns_servers

		tries, maxtries = 1, 10
		okay = True
		ist, soll = 0, len(pending)
		while pending and okay:
			for domain, txt in pending[:]:
				try:
					r = resolver.query(domain, 'TXT')
					for res in r:
						if txt in [i.decode('utf8') for i in res.strings]:
							pending.remove((domain, txt))
							ist += 1
				except dns.exception.DNSException as e:
					pass
				_progress(' + Progress:', ist, soll, '[{0}/{1} tries]'.format(tries, maxtries))

			if not pending:
				break
			tries += 1
			if tries > maxtries:
				logging.error(' ! Maximum tries reached, aborting!')
				okay = False
				break
			for x in range(0, tries):
				_progress(' + Progress:', ist, soll, '[{0}/{1} tries] {2}s'.format(tries, maxtries, tries - x))
				time.sleep(1)
		return okay

	def clean(self):
		logging.info('# Challenge cleanup.')
		url = 'https://api.cloudflare.com/client/v4/zones/{0}/dns_records/'.format(self.zone)
		soll = len(self.needclean)
		for ist, record in enumerate(self.needclean):
			_progress(' + Progress:', ist + 1, soll)
			r = requests.request('DELETE', url + record, headers=self.headers)
			if not r.ok:
				logging.error(' ! Cloudflare API error while deleting record: ({0})\n{1}'.format(r.status_code, r.text))
		self.needclean.clear()


def main(args):
	with open(args.config, 'r') as fp:
		if yaml and (args.config.endswith('.yaml') or args.config.endswith('.yml')):
			config = yaml.full_load(fp)
		else:
			config = json.load(fp)

	error = 0
	issued = 0
	client = ACMEClient(ca_url=args.acme_server, email=args.email)

	if args.revoke or args.revoke_all:
		paths = []
		if args.revoke_all:
			for name, obj in config['domains'].items():
				if 'disabled' in obj and obj['disabled']:
					continue
				paths.append(os.path.join('certs', name, 'cert.pem'))
		else:
			if args.revoke in config['domains']:
				paths.append(os.path.join('certs', args.revoke, 'cert.pem'))
			else:
				logging.error('! Invalid revoke parameter specified!')
				return 1

		for path in paths:
			logging.info('# Revoking %s', path)
			try:
				with open(path, 'rb') as fd:
					pem = fd.read()
			except:
				logging.error(' ! Couldn\'t open file!')
				error = 1
				continue

			cert = x509.load_pem_x509_certificate(pem, default_backend())
			try:
				client.acme_revoke(cert.public_bytes(serialization.Encoding.DER))
				logging.info(' + Success!')
			except ValueError as e:
				logging.error(' ! Error: {0}'.format(e))
				error = 1
				continue

			os.remove(path)
		return error

	for name, obj in config['domains'].items():
		if 'disabled' in obj and obj['disabled']:
			continue

		domains = obj.get('domains', None)
		if not domains:
			logging.error('! No \'domains\' list specified!')
			error = 1
			continue
		chatype = obj.get('challenge', None)
		if chatype not in ['http-01', 'dns-01']:
			logging.error('! No/Invalid \'challenge\' string specified!')
			error = 1
			continue
		chaconf = obj.get(chatype, None)
		if not chaconf:
			logging.error('! No \'%s\' config specified!', chatype)
			error = 1
			continue

		logging.info('# Processing \'%s\' with %d domain name(s) using %s challenge', name, len(domains), chatype)
		logging.info(' * %s', ' '.join(domains))

		certspath = os.path.join('certs', name)
		if not os.path.isdir(certspath):
			os.makedirs(certspath, mode=0o700)

		keypath = os.path.abspath(os.path.join(certspath, 'privkey.pem'))
		csrpath = os.path.abspath(os.path.join(certspath, 'cert.csr'))
		certpath = os.path.abspath(os.path.join(certspath, 'cert.pem'))

		cert = None
		try:
			with open(certpath, 'rb') as fd:
				cert = x509.load_pem_x509_certificate(fd.read(), default_backend())
		except Exception:
			pass

		renew = False
		if cert:
			logging.info('# Found existing certificate:')
			olddomains = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME) \
						 .value.get_values_for_type(x509.DNSName)
			changed = sorted(domains) != sorted(olddomains)
			logging.info(' + Domain name(s) of certificate: %s', 'changed!' if changed else 'unchanged.')
			if changed and not renew:
				logging.info('  * Renewing!')
				renew = True

			timeleft = cert.not_valid_after - datetime.datetime.now()
			logging.info(' + Certificate expires on: %s (%d days)', cert.not_valid_after, timeleft.days)
			if timeleft.days < RENEW_DAYS:
				logging.info('  * Less than %d days!', RENEW_DAYS)
				if not renew:
					logging.info('  * Renewing!')
					renew = True

			if not renew and (args.force or name == args.force_one):
				logging.info(' + Forcing renew!')
				renew = True

		if cert and not renew:
			continue

		challenger = None
		try:
			if chatype == 'http-01':
				challenger = HTTP01Challenger(chaconf, domains)
			elif chatype == 'dns-01':
				challenger = DNS01CloudflareChallenger(chaconf, domains)
		except ValueError as e:
			logging.error('! Challenger error: {0}'.format(e))
			error = 1
			continue

		logging.info('# Creating new order...')
		order = client.acme_order(domains)
		logging.info(' + Success!')

		logging.info('# Requesting challenges...')
		chalist = []
		soll = len(domains)
		for ist, url in enumerate(order['authorizations']):
			domain = order['identifiers'][ist]['value']
			_progress(' + Progress:', ist + 1, soll, domain)
			chalist.append(client.acme_get_challenge(url))

		try:
			logging.info('# Deploying challenge...')
			if not challenger.deploy(chalist):
				challenger.clean()
				error = 1
				continue

			pending = []
			logging.info('# Notifying ACME server...')
			soll = len(chalist)
			for ist, cha in enumerate(chalist):
				domain = cha['identifier']['value']
				mycha = next((i for i in cha['challenges'] if i['type'] == chatype), None)

				_progress(' + Progress:', ist + 1, soll, domain)
				res = client.acme_notify(mycha['url'], mycha['keyauth'])
				if res['status'] == 'invalid':
					_progress(' + Progress:', ist + 1, soll, domain, True)
					logging.error(' ! received \'invalid\' status: %s', res)
					challenger.clean()
					error = 1
					continue
				elif res['status'] == 'pending':
					pending.append(mycha)

			logging.info('# Waiting for %d pending challenges...', len(pending))
			tries, maxtries = 1, 10
			stop = False
			ist, soll = 0, len(pending)
			while pending and not stop:
				for mycha in pending[:]:
					res = client.acme_check_challenge(mycha['url'])
					if res['status'] == 'invalid':
						_progress(' + Progress:', ist, soll, '[{0}/{1} tries]'.format(tries, maxtries), True)
						logging.error(' ! received \'invalid\' status: %s', res)
						stop = True
						break
					elif res['status'] != 'pending':
						pending.remove(mycha)
						ist += 1
					_progress(' + Progress:', ist, soll, '[{0}/{1} tries]'.format(tries, maxtries))

				if not pending or stop:
					break
				tries += 1
				if tries > maxtries:
					logging.error(' ! Maximum tries reached, aborting!')
					stop = True
					break
				for x in range(0, tries):
					_progress(' + Progress:', ist, soll, '[{0}/{1} tries] {2}s'.format(tries, maxtries, tries - x))
					time.sleep(1)

			if stop:
				challenger.clean()
				error = 1
				continue

			logging.info(' + Valid!')
		except KeyboardInterrupt:
			challenger.clean()
			return error
		challenger.clean()

		now = int(time.time())
		logging.info('# Generating private key...')
		privkey, pem = generate_rsa_key()
		with open(os.open(os.path.join(certspath, 'privkey-{}.pem'.format(now)), os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as fp:
			fp.write(pem)

		logging.info('# Generating certificate signing request...')
		csr = x509.CertificateSigningRequestBuilder().subject_name(
			x509.Name([
				x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
		])).add_extension(
			x509.SubjectAlternativeName([
				x509.DNSName(x) for x in domains
			]),
			critical=False
		)
		csr = csr.sign(privkey, hashes.SHA256(), default_backend())
		with open(os.path.join(certspath, 'cert-{}.csr'.format(now)), 'wb') as fp:
			fp.write(csr.public_bytes(serialization.Encoding.PEM))

		logging.info('# Finalizing order...')
		order = client.acme_finalize(order['finalize'], csr.public_bytes(serialization.Encoding.DER))
		logging.info(' + Success!')

		logging.info('# Downloading signed certificate...')
		pem = client.acme_download_cert(order['certificate']).content
		logging.info(' + Success!')

		with open(os.path.join(certspath, 'cert-{}.pem'.format(now)), 'wb') as fp:
			fp.write(pem)

		os.removef(keypath)
		os.removef(csrpath)
		os.removef(certpath)

		os.symlink('privkey-{}.pem'.format(now), keypath)
		os.symlink('cert-{}.csr'.format(now), csrpath)
		os.symlink('cert-{}.pem'.format(now), certpath)
		issued += 1

		copy = obj.get('copy', None)
		if copy:
			for path in _itery(copy.get('privkey', None)):
				path = path.replace('{name}', name)
				logging.info('# Copying private key to: {}'.format(path))
				shutil.copy2(keypath, path)
			for path in _itery(copy.get('cert', None)):
				path = path.replace('{name}', name)
				logging.info('# Copying certificate to: {}'.format(path))
				shutil.copy2(certpath, path)

		for cmd in _itery(obj.get('deploy', None)):
			cmd = cmd.replace('{name}', name) \
					.replace('{privkey}', keypath).replace('{cert}', certpath)
			logging.info('# Running deploy script: %s', cmd)
			r = subprocess.run(cmd, shell=True)
			if r.returncode != 0:
				logging.info(' ! Returned with non-zero returncode: %s', r.returncode)
				error = True
		logging.info('----- ----- -----')

	if issued > 0:
		for cmd in _itery(config.get('alldone', None)):
			logging.info('# Running alldone script: %s', cmd)
			r = subprocess.run(cmd, shell=True)
			if r.returncode != 0:
				logging.info(' ! Returned with non-zero returncode: %s', r.returncode)
				error = True

	return error


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='snacme - Minimal Python3 ACME client')
	parser.add_argument('-c', '--config', default=None, help='config file in JSON or YAML (.yaml or .yml) format')
	parser.add_argument('-f', '--force', action='store_true', help='force renew all certificates')
	parser.add_argument('-fo', '--force-one', metavar='name', help='force renew one certificate')
	parser.add_argument('-r', '--revoke', metavar='name', help='revoke one certificate')
	parser.add_argument('-ra', '--revoke-all', action='store_true', help='revoke all certificates')
	parser.add_argument('--email', help='e-mail address used for account registration')
	parser.add_argument('--staging', action='store_true', help='use Let\'s Encrypt staging server')
	parser.add_argument('--acme-server', metavar='URL', default=None, help='custom ACME server')
	parser.add_argument('--ca-cert', metavar='PEM', help='custom ca-cert for ACME server')
	parser.add_argument('-v', '--verbose', action='store_true', help='debug verbosity')
	args = parser.parse_args()

	if args.verbose:
		logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s]\t(%(funcName)s:%(lineno)d) %(message)s')
	else:
		logging.basicConfig(level=logging.INFO, format='%(message)s')

	if args.ca_cert:
		if not os.path.isfile(args.ca_cert):
			parser.error('The file \'{}\' does not exist!'.format(args.ca_cert))
		CA_CERT = args.ca_cert

	if args.config is None:
		if os.path.isfile('config.json'):
			args.config = 'config.json'
		elif os.path.isfile('config.yaml'):
			args.config = 'config.yaml'
		elif os.path.isfile('config.yml'):
			args.config = 'config.yml'
		else:
			parser.error('Could not find a suitable config file!')
	elif not os.path.isfile(args.config):
		parser.error('Config file \'{}\' does not exist!'.format(args.config))

	if args.email and not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', args.email):
		parser.error('Invalid E-Mail address specified!')

	if args.staging:
		ACME_SERVER = LE_STAGING_ACME_SERVER

	if args.acme_server is None:
		args.acme_server = ACME_SERVER

	url = 'https://' + args.acme_server.split("://")[-1]
	o = urllib.parse.urlparse(url)
	path = o.path.rsplit('/directory')[0]
	args.acme_server = urllib.parse.urlunsplit((o.scheme, o.netloc, path, '', ''))

	ret = main(args)
	if ret != 0:
		sys.exit(ret)
