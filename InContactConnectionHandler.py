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
	def __init__(self):
		self.is_authenticated = False
		self.token_info = None
		self.refresh_info = None
		self.session = None

	def __make_request__(self, *args, **kwargs):
		"""
		Wraps the requests.request() method or requests.session.request()
		method depending on the self.session attribute
		"""
		if self.session:
			return self.session.request(*args, **kwargs)
		else:
			return requests.request(*args, **kwargs)

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
