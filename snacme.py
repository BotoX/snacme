#!/usr/bin/env python3
import os
import sys
import re
import time
import datetime
import logging
import argparse
import base64
import hashlib
import urllib.parse
import requests
import json
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
	if not hasattr(dns.resolver, 'resolve'):
		dns.resolver.resolve = dns.resolver.query
		dns.resolver.Resolver.resolve = dns.resolver.Resolver.query
except ImportError:
	dns = None

from cryptography import x509
from cryptography.utils import int_to_bytes
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils

LE_ACME_SERVER = 'https://acme-v02.api.letsencrypt.org'
LE_STAGING_ACME_SERVER = 'https://acme-staging-v02.api.letsencrypt.org'
ACME_SERVER = LE_ACME_SERVER
RENEW_DAYS_MIN = 30
KEY_ROTATE_DAYS = 30
CA_CERT = None
SUPPORTED_CRYPTO = {
	'rsa-2048': ('rsa', 2048),
	'rsa-4096': ('rsa', 4096),
	'ec-256': ('ec', 256),
	'ec-384': ('ec', 384)
}

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

def generate_key(algo, bits):
	if algo == 'rsa':
		pkey = rsa.generate_private_key(
			public_exponent=65537,
			key_size=bits,
			backend=default_backend()
		)
	elif algo == 'ec':
		curves = {
			256: ec.SECP256R1(),
			384: ec.SECP384R1(),
			521: ec.SECP521R1()
		}
		pkey = ec.generate_private_key(
			curve=curves[bits],
			backend=default_backend()
		)
	else:
		raise ValueError('Unknown cryptography: {0}'.format(algo))

	pem = pkey.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)
	return pkey, pem

def load_key(path):
	with open(path, 'rb') as fp:
		return serialization.load_pem_private_key(
			fp.read(),
			password=None,
			backend=default_backend()
		)

def acme_b64encode(data):
	if isinstance(data, bytes):
		return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')
	else:
		return base64.urlsafe_b64encode(data.encode('utf8')).decode('ascii').rstrip('=')

class ACMEClient():
	def __init__(self, ca_url, algo, email=None):
		self.ca_url = ca_url
		self.email = email
		self._algo = algo
		self.algo, self.bits = SUPPORTED_CRYPTO[algo]

		r = self.api_get(urllib.parse.urljoin(self.ca_url, 'directory'))
		if not r.ok:
			raise ValueError('ACME error while getting directory: ({0})\n{1}'.format(r.status_code, r.text))
		self.directory = r.json()

		self.kid = None
		self.privkey = None
		self.pubkey = None
		self.acme_register()

	def acme_nonce(self):
		r = self.api_head(self.directory['newNonce'])
		if not r.ok:
			raise ValueError('ACME error while requesting new nonce: ({0})\n{1}'.format(r.status_code, r.text))
		nonce = r.headers['Replay-Nonce']
		return nonce

	def acme_register(self):
		accpath = os.path.join('accounts', acme_b64encode(self.ca_url + '/directory'), self._algo)
		if not os.path.isdir(accpath):
			os.makedirs(accpath, mode=0o700)

		acckey = os.path.join(accpath, 'account_key.pem')
		if os.path.isfile(acckey):
			logging.debug('# Using existing account private key: %s', acckey)
			self.privkey = load_key(acckey)
		else:
			logging.info('# Generating new account private key...')
			self.privkey, pem = generate_key(self.algo, self.bits)
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
		r = self.api_post(url, None) # POST-as-GET
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
		r = self.api_post(url, None) # POST-as-GET
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
		r = self.api_post(url, None) # POST-as-GET
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
		if self.algo == 'rsa':
			return self.privkey.sign(
				msg,
				padding.PKCS1v15(),
				hashes.SHA256()
			)
		elif self.algo == 'ec':
			hash_algos = {
				256: hashes.SHA256(),
				384: hashes.SHA384(),
				521: hashes.SHA512()
			}
			sig_der = self.privkey.sign(
				msg,
				ec.ECDSA(hash_algos[self.bits])
			)
			num_bytes = (self.bits + 7) // 8
			r, s = utils.decode_dss_signature(sig_der)
			return int_to_bytes(r, num_bytes) + int_to_bytes(s, num_bytes)

	def jwk(self):
		pubnums = self.pubkey.public_numbers()
		if self.algo == 'rsa':
			return {
				'kty': 'RSA',
				'n': acme_b64encode(int_to_bytes(pubnums.n)),
				'e': acme_b64encode(int_to_bytes(pubnums.e))
			}
		elif self.algo == 'ec':
			return {
				'kty': 'EC',
				'crv': 'P-{0}'.format(self.bits),
				'x': acme_b64encode(int_to_bytes(pubnums.x)),
				'y': acme_b64encode(int_to_bytes(pubnums.y))
 		}

	def jws_header(self):
		if self.algo == 'rsa':
			res = {'alg': 'RS256'}
		elif self.algo == 'ec':
			res = {'alg': 'ES{0}'.format(self.bits)}
		if self.kid:
			res['kid'] = self.kid
		else:
			res['jwk'] = self.jwk()
		return res

	def jws_sign(self, url, payload):
		if payload is not None:
			payload = acme_b64encode(payload)
		else: # POST-as-GET
			payload = ''
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
			r = requests.request(method=method, headers=_headers, url=url, data=data, timeout=30, verify=CA_CERT)
		except Exception as e:
			raise e
		return r

	def api_head(self, url):
		return self._requests_request('HEAD', url)

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
			os.removef(path)
		self.needclean.clear()

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
		self.zone = ''
		self.initialized = False

	def init(self):
		if self.initialized:
			return
		self.initialized = True

		self.domain = min(self.domains, key=len)
		if 'name' in self.config:
			self.domain = self.config['name']
		r = requests.get('https://api.cloudflare.com/client/v4/zones?name={0}'.format(self.domain), headers=self.headers)
		if not r.ok:
			raise ValueError('Cloudflare API error while getting zone: ({0})\n{1}'.format(r.status_code, r.text))
		if not r.json()['result']:
			logging.error('\t! Using Cloudflare domain name: {0}'.format(self.domain))
			logging.error('\t! Is this correct? Use "name" in "dns-01" challenge otherwise.')
			raise ValueError('Cloudflare API returned empty result!')
		self.zone = r.json()['result'][0]['id']

	def deploy(self, chalist):
		self.init()
		pending = []
		url = 'https://api.cloudflare.com/client/v4/zones/{0}/dns_records'.format(self.zone)
		soll = len(chalist)
		for ist, cha in enumerate(chalist):
			domain = cha['identifier']['value']
			mycha = next((i for i in cha['challenges'] if i['type'] == 'dns-01'), None)

			_progress(' + Writing DNS record', ist + 1, soll, domain)
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

		dns_servers = dns.resolver.resolve(self.domain, 'NS')
		dns_servers = [i.to_text() for i in dns_servers]
		dns_servers = [socket.gethostbyname(i) for i in dns_servers]
		resolver = dns.resolver.Resolver()
		resolver.nameservers = dns_servers

		tries, maxtries = 1, 15
		okay = True
		ist, soll = 0, len(pending)
		while pending and okay:
			for domain, txt in pending[:]:
				try:
					r = resolver.resolve(domain, 'TXT')
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

	def dane_tlsa(self, certspath, fingerprints):
		error = 0
		cfgpath = os.path.join(certspath, 'dane-cloudflare.json')
		if not 'dane' in self.config and not os.path.isfile(cfgpath):
			return error

		if not 'dane' in self.config:
			self.config['dane'] = []

		prevhash = fingerprints[0]
		curhash = fingerprints[1]
		nexthash = fingerprints[2]

		danestor = {}
		if os.path.isfile(cfgpath):
			with open(cfgpath, 'r') as fp:
				danestor = json.load(fp)

		records_add = [] # (record, hash)
		records_del = [] # (record, hash, cfid)

		for record in self.config['dane']:
			obj = danestor.get(record)
			if obj:
				# remove previous hash if any
				if prevhash:
					cfid = obj.get(prevhash)
					if cfid:
						records_del.append((record, prevhash, cfid))

				# add current hash if not exists
				cfid = obj.get(curhash)
				if not cfid:
					records_add.append((record, curhash))

				# add next hash if not exists
				cfid = obj.get(nexthash)
				if not cfid:
					records_add.append((record, nexthash))
			else:
				# add current and next hash
				records_add.append((record, curhash))
				records_add.append((record, nexthash))

		for record, obj in danestor.items():
			if record not in self.config['dane']:
				# remove all records which have been removed from the config
				for ahash, cfid in obj.items():
					records_del.append((record, ahash, cfid))

		if not (records_add or records_del):
			return error
		self.init()

		if records_del:
			logging.info('# Deleting {} DANE TLSA records.'.format(len(records_del)))
			url = 'https://api.cloudflare.com/client/v4/zones/{0}/dns_records/'.format(self.zone)
			soll = len(records_del)
			for ist, record in enumerate(records_del):
				_progress(' + Progress:', ist + 1, soll)
				r = requests.request('DELETE', url + record[2], headers=self.headers)
				if r.ok:
					del danestor[record[0]][record[1]]
					if not danestor[record[0]]:
						del danestor[record[0]]
				else:
					logging.error(' ! Cloudflare API error while deleting record: ({0})\n{1}'.format(r.status_code, r.text))
					error = 1

		if records_add:
			logging.info('# Adding {} DANE TLSA records.'.format(len(records_add)))
			url = 'https://api.cloudflare.com/client/v4/zones/{0}/dns_records/'.format(self.zone)
			soll = len(records_add)
			for ist, record in enumerate(records_add):
				_progress(' + Progress:', ist + 1, soll)
				data = json.dumps({
					"type": "TLSA",
					"name": record[0],
					"data": {
						"usage": 3,
						"selector": 1,
						"matching_type": 1,
						"certificate": record[1]
					},
					"ttl": 1
				})
				r = requests.post(url, data=data, headers=self.headers)
				if r.ok:
					cfid = r.json()['result']['id']
					if record[0] in danestor:
						danestor[record[0]][record[1]] = cfid
					else:
						danestor[record[0]] = {record[1]: cfid}
				else:
					logging.error(' ! Cloudflare API error while writing record: ({0})\n{1}'.format(r.status_code, r.text))
					error = 2

		with open(cfgpath, 'w') as fp:
			json.dump(danestor, fp, sort_keys=True, indent=4)

		return error

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


def privkey_manage(client, now, certspath, keypath, keypath_next, force):
	privkey_prev = None
	privkey = None
	privkey_next = None
	privkey_deploy_f = None
	if os.path.isfile(keypath_next):
		keyname = os.readlink(keypath)
		keytime = int(keyname.lstrip('privkey-').rstrip('.pem'))
		keyage = (now - keytime) / 3600 / 24
		current_keypath = keypath

		if keyage > KEY_ROTATE_DAYS or force:
			logging.info('# Generating new next private key...')
			privkey_next, pem = generate_key(client.algo, client.bits)
			with open(os.open(os.path.join(certspath, 'privkey-{}.pem'.format(now)), os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as fp:
				fp.write(pem)

			# load previously used key to remove it from DANE TLSA
			privkey_prev = load_key(keypath)
			current_keypath = keypath_next

			# rotate keys: next -> current, new -> next
			# but only rotate after the new certificate has been issued
			def _rotate(keypath, keypath_next, keyname_next, keyname_new):
				logging.info('# Rotating private key')
				os.removef(keypath)
				os.removef(keypath_next)
				os.symlink(keyname_next, keypath)
				os.symlink(keyname_new, keypath_next)
			keyname_next = os.readlink(keypath_next)
			keyname_new = 'privkey-{}.pem'.format(now)
			privkey_deploy_f = lambda a=keypath, b=keypath_next, c=keyname_next, d=keyname_new: _rotate(a, b, c, d)
		else:
			# load next private key
			privkey_next = load_key(keypath_next)

		# load current private key
		privkey = load_key(current_keypath)
	else:
		logging.info('# Generating initial private key...')
		privkey, pem = generate_key(client.algo, client.bits)
		with open(os.open(os.path.join(certspath, 'privkey-{}.pem'.format(now)), os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as fp:
			fp.write(pem)

		# fake timestamp to avoid possibility of renewing both certificates on the same day
		futurenow = now + (KEY_ROTATE_DAYS * 24 * 3600)
		logging.info('# Generating next private key...')
		privkey_next, pem = generate_key(client.algo, client.bits)
		with open(os.open(os.path.join(certspath, 'privkey-{}.pem'.format(futurenow)), os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as fp:
			fp.write(pem)

		# deploy key late in case of error
		# otherwise we'd end up forcing key rotation because there is a key deployed without a certificate (thinking it was revoked)
		def _deploy(keypath, keypath_next, keyname_cur, keyname_new):
			os.removef(keypath)
			os.removef(keypath_next)
			os.symlink(keyname_cur, keypath)
			os.symlink(keyname_new, keypath_next)
		keyname_cur = 'privkey-{}.pem'.format(now)
		keyname_new = 'privkey-{}.pem'.format(futurenow)
		privkey_deploy_f = lambda a=keypath, b=keypath_next, c=keyname_cur, d=keyname_new: _deploy(a, b, c, d)

	return privkey_prev, privkey, privkey_next, privkey_deploy_f

def process_challenges(client, challenger, chatype, chalist):
	logging.info('# Deploying challenge...')
	if not challenger.deploy(chalist):
		return 1

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
			return 1
		elif res['status'] == 'pending':
			pending.append(mycha)

	logging.info('# Waiting for %d pending challenges...', len(pending))
	tries, maxtries = 1, 15
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
		return 1

	logging.info(' + Valid!')
	return 0

def revoke_certificates(client, config, revoke, revoke_all):
	error = 0
	paths = []
	if revoke_all:
		for name, obj in config['certificates'].items():
			if 'disabled' in obj and obj['disabled']:
				continue
			paths.append(os.path.join('certs', name, 'cert.pem'))
	else:
		if revoke in config['certificates']:
			paths.append(os.path.join('certs', revoke, 'cert.pem'))
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

def fingerprint_pkeys(pkeys):
	# compute SHA256 hash of public key for DANE TLSA
	fingerprints = [*[None] * len(pkeys)]
	for i, pkey in enumerate(pkeys):
		if pkey:
			p = pkey.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
			fingerprints[i] = hashlib.sha256(p).hexdigest()
	return fingerprints


def main(args):
	with open(args.config, 'r') as fp:
		if args.config.endswith('.yaml') or args.config.endswith('.yml'):
			if yaml is None:
				raise ValueError('YAML config specified but python-yaml not installed!')
			try:
				config = yaml.full_load(fp)
			except AttributeError:
				config = yaml.load(fp)
		else:
			config = json.load(fp)

	error = 0
	issued = 0
	client = ACMEClient(ca_url=args.acme_server, email=args.email, algo=args.key_type)

	if args.revoke or args.revoke_all:
		return revoke_certificates(client, config, args.revoke, args.revoke_all)

	for name, obj in config['certificates'].items():
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
		keypath_next = os.path.abspath(os.path.join(certspath, 'privkey-next.pem'))
		csrpath = os.path.abspath(os.path.join(certspath, 'cert.csr'))
		fullchainpath = os.path.abspath(os.path.join(certspath, 'fullchain.pem'))
		certpath = os.path.abspath(os.path.join(certspath, 'cert.pem'))
		chainpath = os.path.abspath(os.path.join(certspath, 'chain.pem'))

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
			if timeleft.days < RENEW_DAYS_MIN:
				logging.info('  * Less than %d days!', RENEW_DAYS_MIN)
				if not renew:
					logging.info('  * Renewing!')
					renew = True

			if not renew and (args.force or name == args.force_one):
				logging.info(' + Forcing renew!')
				renew = True

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

		if cert and not renew:
			if hasattr(challenger, 'dane_tlsa'):
				# load private keys
				privkey = load_key(keypath)
				privkey_next = load_key(keypath_next)
				# calculate fingerprints
				fingerprints = fingerprint_pkeys([None, privkey, privkey_next])
				# call DANE TLSA handler
				challenger.dane_tlsa(certspath, fingerprints)
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
			if process_challenges(client, challenger, chatype, chalist):
				error = 1
				continue
		except KeyboardInterrupt:
			return 1
		finally:
			challenger.clean()

		now = int(time.time())
		force_key = args.force_key or not cert # force key rotation if certifcate was revoked(deleted)
		privkey_prev, \
		privkey, \
		privkey_next, \
		privkey_deploy_f = privkey_manage(client, now, certspath, keypath, keypath_next, force_key)

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

		with open(os.path.join(certspath, 'fullchain-{}.pem'.format(now)), 'wb') as fp:
			fp.write(pem)

		# Generate cert.pem and chain.pem from fullchain.pem
		pem_parts = re.findall(b'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n', pem, re.DOTALL)

		with open(os.path.join(certspath, 'cert-{}.pem'.format(now)), 'wb') as fp:
			fp.write(pem_parts[0])

		with open(os.path.join(certspath, 'chain-{}.pem'.format(now)), 'wb') as fp:
			fp.write(b'\n'.join(pem_parts[1:]))

		fingerprints = fingerprint_pkeys([privkey_prev, privkey, privkey_next])

		if hasattr(challenger, 'dane_tlsa'):
			challenger.dane_tlsa(certspath, fingerprints)

		if privkey_deploy_f:
			privkey_deploy_f()

		os.removef(csrpath)
		os.removef(fullchainpath)
		os.removef(certpath)
		os.removef(chainpath)

		os.symlink('cert-{}.csr'.format(now), csrpath)
		os.symlink('fullchain-{}.pem'.format(now), fullchainpath)
		os.symlink('cert-{}.pem'.format(now), certpath)
		os.symlink('chain-{}.pem'.format(now), chainpath)
		issued += 1

		copy = obj.get('copy', None)
		if copy:
			for key, path in [('privkey', keypath), ('fullchain', fullchainpath), ('cert', certpath), ('chain', chainpath)]:
				for target in _itery(copy.get(key, None)):
					target = target.replace('{name}', name)
					logging.info('# Copying {} key to: {}'.format(key, target))
					shutil.copy2(path, target)

		for cmd in _itery(obj.get('deploy', None)):
			cmd = cmd.replace('{name}', name) \
					.replace('{privkey}', keypath).replace('{fullchain}', fullchainpath) \
					.replace('{cert}', certpath).replace('{chain}', chainpath)
			logging.info('# Running deploy script: %s', cmd)
			r = subprocess.run(cmd, shell=True)
			if r.returncode != 0:
				logging.info(' ! Returned with non-zero returncode: %s', r.returncode)
				error = 1
		logging.info('----- ----- -----')

	if issued > 0:
		for cmd in _itery(config.get('alldone', None)):
			logging.info('# Running alldone script: %s', cmd)
			r = subprocess.run(cmd, shell=True)
			if r.returncode != 0:
				logging.info(' ! Returned with non-zero returncode: %s', r.returncode)
				error = 1

	return error


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='snacme - Minimal Python3 ACME client')
	parser.add_argument('-c', '--config', default=None, help='config file in JSON or YAML (.yaml or .yml) format')
	parser.add_argument('-f', '--force', action='store_true', help='force renew all certificates')
	parser.add_argument('-fo', '--force-one', metavar='name', help='force renew one certificate')
	parser.add_argument('-fk', '--force-key', action='store_true', help='force private key rotation when renewing certificates')
	parser.add_argument('-r', '--revoke', metavar='name', help='revoke one certificate')
	parser.add_argument('-ra', '--revoke-all', action='store_true', help='revoke all certificates')
	parser.add_argument('-t', '--key-type', default='ec-384', metavar='type',
		choices=SUPPORTED_CRYPTO.keys(),
		help='Key type to generate. Valid choices: %(choices)s (default: %(default)s)')
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
