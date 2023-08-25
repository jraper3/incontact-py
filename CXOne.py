"""
This module's porpose is to provide a high-level connection abstraction
to the NICE CXOne REST APIs, using a requests-compatible library and
leveraging the most modern OAuth2 backend application authentication
methods available.
"""
from contextlib import contextmanager
from base64 import b64decode

from oauthlib.oauth2 import LegacyApplicationClient
from oauthlib.oauth2.rfc6749.errors import TokenExpiredError
from requests_oauthlib import OAuth2Session
import requests

class CXOneConnectionHandler:
	"""
	This class operates as in interface to provide a "batteries included"
	connection to the NICE CXOne REST API, handling authentication and
	the actual requests itself, abstracting away as many "Under the Hood"
	mechanics as possible. This class exposes a make_request() method,
	which takes endpoint as a parameter in the form of a URL fragment
	as documented at https://developer.niceincontact.com, with or without
	a trailing slash (e.g. '/server-time' or 'server-time').
	"""
	def __init__(self, issuer, client_id, client_secret, access_key,
		access_secret, version='v27.0'):
		self.client = LegacyApplicationClient(client_id=client_id)
		self.session =  OAuth2Session(client=self.client)
		self.issuer = issuer
		self.client_id = client_id
		self.client_secret = client_secret
		self.access_key = access_key
		self.access_secret = access_secret
		self.version = version

	def get_token(self):
		"""
		This method is available to be called directly, but the
		make_request() method will also check for a token before making
		the API request, so this calling this method directly will not 
		typically be necessary.
		"""
		discovery_endpoint = f'{self.issuer}/.well-known/'+ \
			'openid-configuration'
		discovery_response = requests.get(discovery_endpoint)
		discovery_response.raise_for_status()
		discovery_info = discovery_response.json()
		self.session.fetch_token(
			token_url=discovery_info['token_endpoint'],
			client_id=self.client_id,
			client_secret=self.client_secret,
			username=self.access_key,
			password=self.access_secret
		)

	def make_request(self, method, endpoint, version=None, params=None,
		json=None, data=None, headers=None):
		if not self.session.authorized:
			self.get_token()
		if not version:
			version = self.version
		if endpoint[0] == '/':
			endpoint = endpoint[1:]
		uri = f'{self.issuer}/inContactAPI/services/{version}/{endpoint}'
		try:
			return self.session.request(
				method, 
				uri, 
				params=params, 
				json=json, 
				data=data
			)
		except TokenExpiredError:
			self.get_token()
			return self.session.request(
				method, 
				uri, 
				params=params, 
				json=json, 
				data=data
			)

class CXOneClient(CXOneConnectionHandler):
	def get_server_time(self):
		"""
		Wraps the GET /server-time endpoint as documented in the
		API documentation. Can take a dictionary of key value pars
		where the key is the field name and the value is the field
		value. Returns a requests Response object.
		"""
		return self.make_request('GET', '/server-time')

	def get_contacts(self, **kwargs):
		"""
		Wraps the GET /contacts/completed endpoint as documented in the
		API documentation. Can take a dictionary of key value pars
		where the key is the field name and the value is the field
		value. Returns a requests Response object.
		"""
		return self.make_request(
			'GET',
			'/contacts/completed',
			params=kwargs
		)

	def script_search(self, **kwargs):
		"""
		Wraps the GET /scripts/search endpoint as documented in the
		API documentation. Can take a dictionary of key value pars
		where the key is the field name and the value is the field
		value. Returns a requests Response object.
		"""
		return self.make_request(
			'GET',
			'/scripts/search',
			params=kwargs
		)

	def get_script_by_id(self, script_id):
		"""
		Wraps the GET /scripts/{scriptId} endpoint as documented in the
		API documentation. Can take a dictionary of key value pars
		where the key is the field name and the value is the field
		value. Returns a requests Response object.
		"""
		return self.make_request(
			'GET',
			f'/scripts/{script_id}'
		)

	def get_script_by_name(self, script_name):
		"""
		For clarity of purpose, exposes a method to get scripts by name
		instead of id. This method simply wraps the get_script_by_id()
		method and returns the result as the API endpoint takes either
		identifier.
		"""
		return self.get_script_by_id(script_name)

	def get_script_to_file(self, script, file_object):
		"""
		Taking either script name or id as script and a file-like object
		that implements the .write() method with a string as a parameter,
		calls the get_script_by_id() method and writes the response to a
		the file.
		"""
		response = self.get_script_by_id(script)
		response.raise_for_status()
		file_object.write(b64decode(response.json()['body'].encode()).decode())

class BadlyFormattedRequest(Exception):
	pass
