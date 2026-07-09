from __future__ import annotations
from typing import TYPE_CHECKING

import json
import http.client
import logging
import ssl as _ssl
import warnings
from urllib import error, request
import time, threading

if TYPE_CHECKING:
	from ..valt import VALT


class ValtAuth:
	def auth(self: VALT):
		# Authenticate to VALT server
		# Sets accesstoken value to 0 if the authentication attempt fails.
		if self.username != "None" and self.username != "" and self.username is not None and self.password != "None" and self.password != "" and self.password is not None and self.baseurl is not None:
			values = {"username": self.username, "password": self.password}
			self.logger.debug(__name__ + ": " + self.baseurl)
			self.logger.debug(__name__ + ": " + self.username)
			url = self.baseurl + 'login'
			data = self.send_to_valt(url, values=values)
			self.lastauthtime = time.time()
			if isinstance(data, dict):
				self.accesstoken = data['data']['access_token']
				self.errormsg = None
				self.logger.info(__name__ + ": " + "Authenticated to VALT")
				self.version = self.get_version()
				if self.version and self.version != 0:
					self.major_version = self.version.split(".")[0]
					self.minor_version = self.version.split(".")[1]
					self.patch_level = "0"
					if self.major_version == "6":
						parts = self.version.split(".")
						self.patch_level = parts[2] if len(parts) > 2 else "0"
				else:
					self.logger.error(__name__ + ": " + "Unable to determine VALT version")
					self.version = "0.0.0"
					self.major_version = "0"
					self.minor_version = "0"
					self.patch_level = "0"
				self.logger.info(__name__ + ": " + "Valt Version: " + str(self.version))
				self.reauthenticate(self.success_reauth_time)
			else:
				self.logger.error(__name__ + ": " + "Authentication FAILED")
				self.accesstoken = 0
				self.reauthenticate(self.failure_reauth_time)
	def reauthenticate(self: VALT, reauthtime):
		self.logger.info(__name__ + ":" + " Next authentication attempt in " + str(reauthtime) + " seconds")
		if hasattr(self, 'reauth'):
			self.reauth.cancel()
		self.reauth = threading.Timer(reauthtime, self.auth)
		self.reauth.daemon = True
		self.reauth.start()

	def change_server(self: VALT, valt_address, valt_username, valt_password):
		if valt_address != "None" and valt_address != "" and valt_address is not None:
			self.disconnect()
			if valt_address.find("http", 0, 4) == -1:
				self.baseurl = 'http://' + valt_address + '/api/v3/'
			else:
				self.baseurl = valt_address + '/api/v3/'
		else:
			self.baseurl = None
		self.username = valt_username
		self.password = valt_password
		self.auth()
		self.start_room_check_thread()

	@staticmethod
	def test_connection(valt_address, valt_username, valt_password, timeout=5):
		# Standalone check: does not require an existing VALT instance and has no
		# side effects (no accesstoken/observer changes, no reauthenticate loop).
		logger = logging.getLogger(__name__)
		values = {"username": valt_username, "password": valt_password}
		params = json.dumps(values).encode('utf-8')
		if valt_address.find("http", 0, 4) == -1:
			valt_baseurl = 'http://' + valt_address + '/api/v3/'
		else:
			valt_baseurl = valt_address + '/api/v3/'
		logger.debug(__name__ + ": " + "Testing Connection to VALT server")
		logger.debug(__name__ + ": " + valt_baseurl)
		logger.debug(__name__ + ": " + valt_username)
		logger.debug(__name__ + ": ***")

		ctx = _ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = _ssl.CERT_NONE
		try:
			req = request.Request(valt_baseurl + 'login')
			req.add_header('Content-Type', 'application/json')
			request.urlopen(req, params, timeout=timeout, context=ctx)
		except error.HTTPError as e:
			logger.warning(__name__ + ": " + str(e))
			if str(e) == "HTTP Error 401: Unauthorized":
				return False, "Invalid Username or Password"
			return False, "Unable to Connect"
		except error.URLError as e:
			logger.warning(__name__ + ": " + str(e))
			return False, "Unable to Connect"
		except http.client.HTTPException as e:
			logger.warning(__name__ + ": " + str(e))
			return False, "Unable to Connect"
		except Exception as e:
			logger.warning(__name__ + ": " + str(e))
			return False, "Unable to Connect"
		else:
			return True, None
	@property
	def accesstoken(self: VALT):
		return self._accesstoken
	@accesstoken.setter
	def accesstoken(self: VALT,newmsg):
		self._accesstoken = newmsg
		for callback in self._accesstoken_observers:
			callback(self._accesstoken)
	@property
	def connected(self: VALT) -> bool:
		return self.accesstoken != 0
	def bind_to_accesstoken(self: VALT, callback):
		self._accesstoken_observers.append(callback)

	# ── Deprecated aliases ────────────────────────────────────────

	def changeserver(self: VALT, valt_address, valt_username, valt_password):
		warnings.warn("changeserver is deprecated and will be removed in a future version. Use change_server instead.", DeprecationWarning, stacklevel=2)
		return self.change_server(valt_address, valt_username, valt_password)

	def testconnection(self: VALT, valt_address, valt_username, valt_password):
		warnings.warn("testconnection is deprecated and will be removed in a future version. Use test_connection instead.", DeprecationWarning, stacklevel=2)
		return self.test_connection(valt_address, valt_username, valt_password)
