# Standard Library Imports
from base64 import b64encode
from datetime import datetime, timedelta

# Third Party Library Imports
import requests

# Custom Imports

"""
This module's purpose is to provide the low-level connection abstraction
to the inContact REST APIs using the requests library.

Classes:
InContactConnectionHandler

Exceptions:
AuthenticationError

Functions:


"""

class InContactConnectionHandler:
	"""
	This class is meant as the main low level connection to inContact
	and is to handle the actual API requests, authentication, and 
	everything that happens "Under the hood".
	"""
	def __init__(self, version='20.0'):
		self.is_authenticated = False
		self.token_info = None
		self.refresh_info = None
		self.session = None
		self.version = version

	def __make_request__(self, *args, **kwargs):
		"""
		Wraps the requests.request() method or requests.session.request()
		method depending on the self.session attribute
		"""
		if self.session:
			response =  self.session.request(*args, **kwargs)
		else:
			response = requests.request(*args, **kwargs)

		if response.status_code == 401:
			raise AuthenticationError(
				status_code = response.status_code,
				response_message = response.text
			)

		return response 

	def __get_auth__(self, username, password, bu, vendor, app):
		"""
		Take credentials and make auth request to inContact. Return
		results as a dict.

		TODO:
			- Allow other types of authentication other than password auth

		"""
		url = 'https://api.incontact.com/InContactAuthorizationServer/Token'
		token = b64encode(f'{app}@{vendor}:{bu}'.encode()).decode()
		headers = {'Authorization': f'basic {token}'}
		request_body = {
			'grant_type': 'password',
			'username': username,
			'password': password,
			'scope': ''
		}
		response = self.__make_request__(
			'POST',
			url,
			headers=headers,
			json=request_body
		)
		if response.status_code != 200:
			raise AuthenticationError(
				status_code = response.status_code,
				response_message = response.text
			)

		return response.json()

	def __get_refresh__(self):
		"""
		Make refresh request to inContact, assuming that refresh_info
		is populated, and return refresh info as a dict.
		"""
		if not self.refresh_info:
			response_message = 'Refresh info not available. Please '
			response_message += 'authenticate and try again.'
			raise RefreshError(response_message=response_message)
		url = self.refresh_info['refresh_uri']
		app = self.refresh_info['app']
		vendor = self.refresh_info['vendor']
		bu = self.refresh_info['bu']
		token = b64encode(f'{app}@{vendor}:{bu}'.encode()).decode()
		headers = {'Authorization': f'basic {token}'}
		request_body = {
			'grant_type': 'refresh_token',
			'refresh_token': self.refresh_info['refresh_token']
		}
		response = self.__make_request__(
			'POST',
			url,
			headers=headers,
			json=request_body
		)
		if response.status_code != 200:
			raise RefreshError(
				status_code = response.status_code,
				response_message = response.text
			)
		return response.json()


	def get_auth(self, username, password, bu, vendor, app):
		"""
		Fetch auth info from inContact, set self.token_info and
		self.refresh_info. Set self.is_authenticated = True. Return
		auth info as a dict.

		TODO:
			- Allow other types of authentication other than password auth
		"""
		auth_info = self.__get_auth__(username, password, bu, vendor, app)
		self.token_info = {
			'access_token': auth_info['access_token'],
			'token_type': auth_info['token_type'],
			'base_uri': auth_info['resource_server_base_uri'],
			'expire_time': datetime.now() + \
				timedelta(seconds=auth_info['expires_in'])
		}
		self.refresh_info = {
			'refresh_token': auth_info['refresh_token'],
			'refresh_uri': auth_info['refresh_token_server_uri'],
			'refresh_time': self.token_info['expire_time'] - \
				timedelta(seconds=300),
			'bu': auth_info['bus_no'],
			'vendor': vendor,
			'app': app
		}
		self.is_authenticated = True
		return auth_info

	def get_refresh(self):
		"""
		Fetch auth info from inContact from refresh, set self.token_info and
		self.refresh_info. Set self.is_authenticated = True. Return
		auth info as a dict.
		"""
		auth_info = self.__get_refresh__()
		self.token_info['access_token'] = auth_info['access_token']
		self.token_info['token_type'] = auth_info['token_type']
		self.token_info['base_uri'] = auth_info['resource_server_base_uri']
		self.token_info['expire_time'] = datetime.now() + \
			timedelta(seconds=auth_info['expires_in'])

		self.refresh_info['refresh_token'] = auth_info['refresh_token']
		self.refresh_info['refresh_uri'] = auth_info['refresh_token_server_uri']
		self.refresh_info['refresh_time'] = self.token_info['expire_time'] - \
			timedelta(seconds=300)
			
		self.is_authenticated = True
		return auth_info


	def make_request(self, method, endpoint, version=None, params=None, 
		json=None, headers={}):
		"""
		A batteries-included version of __make_request__, checks
		self.is_authenticated, builds URL automatically (assuming version if
		not supplied), and builds the auth header for you (if not using a
		session).

		Take method (HTTP Verb), endpoint (e.g. 'agents/skills'), optionally
		version, optionally params (dict to be passed in as URL params), 
		optionally json (dict to be serialized to JSON string and passed as
		request body), and headers ('Authorization' header overwritten if
		supplied) and return a requests.Reponse object 
		"""
		if not self.is_authenticated:
			response_message = 'You must call get_auth() first.'
			raise AuthenticationError(response_message=response_message)

		if not version:
			version = self.version

		if not self.session:
			token = self.token_info['access_token']
			token_type = self.token_info['token_type']
			headers['Authorization'] = f'{token_type} {token}'

		uri = f'{self.token_info["base_uri"]}services/v{version}/{endpoint}'
		return self.__make_request__(
			method,
			uri,
			headers=headers,
			json=json,
			params=params
		)

	def check_token_validity(self, verify=False, refresh_if_needed=True):
		"""
		Takes 2 flags, and checks validity of a current token nas boolean. 
		If verify argument is True, we'll make a request to inContact to 
		make sure they are accepting the token. If refresh_if_needed is 
		True, we'll check if we're within the last 5 minutes of token 
		validity and if so, we'll call the refresh method.
		"""
		if verify:
			try:
				response = self.make_request(
					'GET',
					'server-time'
				).raise_for_status()
				self.is_authenticated = True
			except (AuthenticationError, requests.exceptions.HTTPError):
				self.is_authenticated = False
				return self.is_authenticated
		if not self.is_authenticated:
			return self.is_authenticated
		if datetime.now() >= self.token_info['expire_time']:
			self.is_authenticated = False
			return self.is_authenticated
		if all([
			refresh_if_needed,
			datetime.now() > self.refresh_info['refresh_time']
		]):
			self.get_refresh()
		return self.is_authenticated
	

class AuthenticationError(Exception):
	"""
	Exception to handle bad authentication requests or unauthenticated
	requests.
	"""
	def __init__(self, status_code=None, response_message=None):
		message = 'The request was not authenticated.'
		if status_code:
			message += f'The server responded with: {status_code}'
		if response_message:
			message += f'\n\t:{response_message}.'
		super().__init__(message)

class RefreshError(AuthenticationError):
	"""
	Exception to handle cases when we aren't able to refresh a
	token
	"""
	pass
