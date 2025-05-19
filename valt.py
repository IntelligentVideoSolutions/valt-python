# VALT API Python Module
# Version 2.10
# Last Updated: 2/10/2025
# Compatible with Valt Versions 5.x and probably 6.x

import json
import http.client, urllib.error, urllib.request, urllib.parse
import os, ssl, time, threading
import logging

class VALT:
	def __init__(self, valt_address, valt_username, valt_password, timeout=5,logpath="ivs.log", **kwargs):
		if (not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None)):
			ssl._create_default_https_context = ssl._create_unverified_context
		if valt_address != "None" and valt_address != "" and valt_address is not None:
			if valt_address.find("http", 0, 4) == -1:
				self.baseurl = 'http://' + valt_address + '/api/v3/'
			else:
				self.baseurl = valt_address + '/api/v3/'
		else:
			self.baseurl = None
		if logging.getLogger("kivy").hasHandlers():
			self.logger = logging.getLogger("kivy").getChild(__name__)
		else:
			self.logger = logging.getLogger(__name__)
			#logging.basicConfig(filename=logpath, level=logging.DEBUG)
			logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt='%Y-%m-%d %H:%M:%S', handlers=[logging.FileHandler(logpath), logging.StreamHandler()])
			# logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))
		self.username = valt_username
		self.password = valt_password
		self.success_reauth_time = 28800
		self.failure_reauth_time = 30
		self.logpath = logpath
		self._errormsg_observers = []
		self._errormsg = None
		self.testmsg = None
		self.accesstoken = 0
		self.httptimeout = int(timeout)
		self.kill_threads = False
		self.auth()
		self._selected_room_status = 99

		self.run_check_room_status = False
		self._observers =  []

		if 'room' in kwargs:
			try:
				self.selected_room = int(kwargs['room'])
			except:
				self.selected_room = None
		else:
			self.selected_room = None

		if 'room_check_interval' in kwargs:
			self.room_check_interval = int(kwargs['room'])
		else:
			self.room_check_interval = 5

		self.start_room_check_thread()


	def auth(self):
		# Authenticate to VALT server
		# Sets accesstoken value to 0 if the authentication attempt fails.
		if self.username != "None" and self.username != "" and self.username is not None and self.password != "None" and self.password != "" and self.password is not None and self.baseurl is not None:
			values = {"username": self.username, "password": self.password}
			params = json.dumps(values).encode('utf-8')
			self.logger.debug(__name__ + ": " + self.baseurl)
			self.logger.debug(__name__ + ": " + self.username)

			self.lastauthtime = time.time()
			try:
				req = urllib.request.Request(self.baseurl + 'login')
				req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.accesstoken = 0
				self.logger.error(__name__ + ": " + "Authentication FAILED")
				self.handleerror(e)
			# return 0
			except urllib.error.URLError as e:
				self.accesstoken = 0
				self.logger.error(__name__ + ": " + "Authentication FAILED")
				self.handleerror(e)
			# return 0
			except http.client.HTTPException as e:
				self.accesstoken = 0
				self.logger.error(__name__ + ": " + "Authentication FAILED")
				self.handleerror(e)
			# return 0
			except Exception as e:
				self.accesstoken = 0
				self.logger.error(__name__ + ": " + "Authentication FAILED")
				self.handleerror(e)
			# return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
				else:
					self.accesstoken = data['data']['access_token']
					self.errormsg = None
					self.logger.info(__name__ + ": " + "Authenticated to VALT")
					self.version = self.getversion()
					self.logger.info(__name__ + ": " + "Valt Version: " + self.version)
					self.reauthenticate(self.success_reauth_time)

	def isrecording(self, room):
		# Function to check if the specified room is currently recording
		# Returns true if the specified room is recording
		# Returns False if the room is not recording
		# Returns 2 if an error is encountered
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'rooms/info/' + str(room) + '?access_token=' + self.accesstoken
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 2
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 2
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 2
			except Exception as e:
				self.handleerror(e)
				return 2
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 2
				else:
					return data['data']['has_recording']

	def getrecordingid(self, room):
		# Function to get the current active recording id in the specified room
		# Returns true if the specified room is recording
		# Returns False if the room is not recording
		# Returns 2 if an error is encountered
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'rooms/info/' + str(room) + '?access_token=' + self.accesstoken
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					# print data
					if "recording" in data['data'].keys():
						return data['data']['recording']['id']
					else:
						self.handleerror("No Recording")
						return 0

	def startrecording(self, room, name, **kwargs):
		# Function to start recording in the specified room.
		# Returns recording id on success and 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			if self.isrecording(room) != True:
				if 'author' in kwargs:
					values = {"name": name, "author": kwargs['author']}
				else:
					values = {"name": name}

				url = self.baseurl + 'rooms/' + str(room) + '/record/start' + '?access_token=' + self.accesstoken
				params = json.dumps(values).encode('utf-8')
				try:
					req = urllib.request.Request(url)
					req.add_header('Content-Type', 'application/json')
					response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
				except urllib.error.HTTPError as e:
					self.handleerror(e)
					return 0
				except urllib.error.URLError as e:
					self.handleerror(e)
					return 0
				except http.client.HTTPException as e:
					self.handleerror(e)
					return 0
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					if 'author' in kwargs:
						self.logger.info(__name__ + ": " + "Recording " + name + " started in " + str(self.getroomname(room)) + " by " + str(self.getusername(kwargs['author'])))
					else:
						self.logger.info(__name__ + ": " + "Recording " + name + " started in " + str(self.getroomname(room)))
					try:
						data = json.load(response)
					except Exception as e:
						self.handleerror(e)
						return 0
					else:
						if room == self.selected_room:
							self.selected_room_status = 2
						return data['data']['id']
			else:
				self.handleerror("Room Already Recording")
				return 0

	def stoprecording(self, room):
		# Function to stop recording in the specified room.
		# Returns recording id on success and 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			if self.isrecording(room) == True:
				url = self.baseurl + 'rooms/' + str(room) + '/record/stop' + '?access_token=' + self.accesstoken

				values = {"nothing": "nothing"}
				params = json.dumps(values).encode('utf-8')
				try:
					req = urllib.request.Request(url)
					req.add_header('Content-Type', 'application/json')
					response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
				except urllib.error.HTTPError as e:
					self.handleerror(e)
					return 0
				except urllib.error.URLError as e:
					self.handleerror(e)
					return 0
				except http.client.HTTPException as e:
					self.handleerror(e)
					return 0
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					self.logger.info(__name__ + ": " + "Recording stopped in " + str(self.getroomname(room)))
					try:
						data = json.load(response)
					except Exception as e:
						self.handleerror(e)
						return 0
					else:
						# print data
						if room == self.selected_room:
							self.selected_room_status = 1
						return data['data']['id']
			else:
				self.handleerror("No Recording")
				return 0

	def pauserecording(self, room):
		# Function to pause recording in the specified room.
		# Returns recording id on success and 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			if self.isrecording(room) == True:
				if self.ispaused(room) != True:
					url = self.baseurl + 'rooms/' + str(room) + '/record/pause' + '?access_token=' + self.accesstoken
					values = {"nothing": "nothing"}
					params = json.dumps(values).encode('utf-8')
					try:
						req = urllib.request.Request(url)
						req.add_header('Content-Type', 'application/json')
						response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
					except urllib.error.HTTPError as e:
						self.handleerror(e)
						return 0
					except urllib.error.URLError as e:
						self.handleerror(e)
						return 0
					except http.client.HTTPException as e:
						self.handleerror(e)
						return 0
					except Exception as e:
						self.handleerror(e)
						return 0
					else:
						self.logger.info(__name__ + ": " + "Recording paused in " + str(self.getroomname(room)))
						try:
							data = json.load(response)
						except Exception as e:
							self.handleerror(e)
							return 0
						else:
							if room == self.selected_room:
								self.selected_room_status = 3
							return data['data']['id']
				else:
					self.handleerror("Room Paused")
					return 0
			else:
				self.handleerror("No Recording")
				return 0

	def resumerecording(self, room):
		# Function to resume recording in the specified room.
		# Returns recording id on success and 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			if self.isrecording(room) == True:
				if self.ispaused(room) == True:
					url = self.baseurl + 'rooms/' + str(room) + '/record/resume' + '?access_token=' + self.accesstoken
					values = {"nothing": "nothing"}
					params = json.dumps(values).encode('utf-8')
					try:
						req = urllib.request.Request(url)
						req.add_header('Content-Type', 'application/json')
						response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
					except urllib.error.HTTPError as e:
						self.handleerror(e)
						return 0
					except urllib.error.URLError as e:
						self.handleerror(e)
						return 0
					except http.client.HTTPException as e:
						self.handleerror(e)
						return 0
					except Exception as e:
						self.handleerror(e)
						return 0
					else:
						self.logger.info(__name__ + ": " + "Recording resumed in " + str(self.getroomname(room)))
						try:
							data = json.load(response)
						except Exception as e:
							self.handleerror(e)
							return 0
						else:
							if room == self.selected_room:
								self.selected_room_status = 2
							return data['data']['id']
				else:
					self.handleerror("Room Not Paused")
					return 0
			else:
				self.handleerror("No Recording")
				return 0

	def addmarker(self, room, markername, color="red"):
		# Function to add a marker current recording in specified room.
		# Returns 99 if not currently authenticated to VALT
		# Returns 1 if successful.
		# Returns 0 on failure.
		if self.accesstoken == 0:
			return 99
		else:
			if self.isrecording(room) == True:
				url = self.baseurl + 'rooms/' + str(room) + '/record/markers' + '?access_token=' + self.accesstoken
				if self.isrecording(room):
					markertime = self.getrecordingtime(room)
					if markertime > 0:
						values = {"event": markername, "time": markertime, "color": color}
						params = json.dumps(values).encode('utf-8')
						self.logger.debug(__name__ + ":" + url)
						self.logger.debug(__name__ + ":" + str(params))
						try:
							req = urllib.request.Request(url)
							req.add_header('Content-Type', 'application/json')
							response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
						except urllib.error.HTTPError as e:
							self.handleerror(e)
							return 0
						except urllib.error.URLError as e:
							self.handleerror(e)
							return 0
						except http.client.HTTPException as e:
							self.handleerror(e)
							return 0
						except Exception as e:
							self.handleerror(e)
							return 0
						else:
							self.logger.info(__name__ + ": " + "Marker " + markername + " added in " + str(self.getroomname(room)))
							try:
								data = json.load(response)
							except Exception as e:
								self.handleerror(e)
								return 0
							else:
								return 1
			else:
				self.handleerror("No Recording")
				return 0

	def addcomment(self, room, markername, color="red"):
		# Function to add a comment current recording in specified room.
		# Returns 99 if not currently authenticated to VALT
		# Returns 1 if successful.
		# Returns 0 on failure.
		if self.accesstoken == 0:
			return 99
		else:
			if self.isrecording(room) == True:
				if self.version[0] == "6":
					url = self.baseurl + 'rooms/' + str(room) + '/record/comments' + '?access_token=' + self.accesstoken
				elif self.version[0] == "5":
					url = self.baseurl + 'rooms/' + str(room) + '/record/markers' + '?access_token=' + self.accesstoken
				else:
					self.logger.error(__name__ + ": Unable to Determine VALT version")
					return 0
				if self.isrecording(room):
					markertime = self.getrecordingtime(room)
					if markertime > 0:
						values = {"event": markername, "time": markertime, "color": color}
						params = json.dumps(values).encode('utf-8')
						self.logger.debug(__name__ + ":" + url)
						self.logger.debug(__name__ + ":" + str(params))
						try:
							req = urllib.request.Request(url)
							req.add_header('Content-Type', 'application/json')
							response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
						except urllib.error.HTTPError as e:
							self.handleerror(e)
							return 0
						except urllib.error.URLError as e:
							self.handleerror(e)
							return 0
						except http.client.HTTPException as e:
							self.handleerror(e)
							return 0
						except Exception as e:
							self.handleerror(e)
							return 0
						else:
							self.logger.info(__name__ + ": " + "Comment " + markername + " added in " + str(self.getroomname(room)))
							try:
								data = json.load(response)
							except Exception as e:
								self.handleerror(e)
								return 0
							else:
								return 1
			else:
				self.handleerror("No Recording")
				return 0

	def getrecordingtime(self, room):
		# Function to add a marker current recording in specified room.
		# Returns current time index on sucess.
		# Returns 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			if self.isrecording(room) == True:
				url = self.baseurl + 'rooms/info/' + str(room) + '?access_token=' + self.accesstoken
				try:
					req = urllib.request.Request(url)
					# req.add_header('Content-Type', 'application/json')
					response = urllib.request.urlopen(req, timeout=self.httptimeout)
				except urllib.error.HTTPError as e:
					self.handleerror(e)
					return 0
				except urllib.error.URLError as e:
					self.handleerror(e)
					return 0
				except http.client.HTTPException as e:
					self.handleerror(e)
					return 0
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					try:
						data = json.load(response)
					except Exception as e:
						self.handleerror(e)
						return 0
					else:
						return data['data']['recording']['time']
			else:
				self.handleerror("No Recording")
				return 0

	def ispaused(self, room):
		# Function to check if specified room is currently recording and paused.
		# Returns true if room is currently paused
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'rooms/' + str(room) + '/status?access_token=' + self.accesstoken
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					if data['data']['status'] == 'paused':
						return True
					else:
						return False

	def islocked(self, room):
		# Function to check if specified room is currently locked.
		# Returns true if room is currently locked.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'rooms/' + str(room) + '/status?access_token=' + self.accesstoken

			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					# print data
					if data['data']['status'] == 'locked':
						return True
					else:
						return False

	def getcameras(self, room):
		# Function to return a list of all cameras in the specified room.
		# Returns a list of cameras if successful. Each list item is actually a dictionary containing information about that camera.
		# Returns 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'admin/rooms/' + str(room) + '/cameras?access_token=' + self.accesstoken
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					pass
			if data['data']['cameras']:
				return data['data']['cameras']
			else:
				self.handleerror("No Cameras")
				return 0

	def getrooms(self):
		# Function to return a list of all rooms.
		# Returns a list of rooms if successful. Each list item is actually a dictionary containing information about that room.
		# Returns 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'rooms/info?access_token=' + self.accesstoken
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					pass
			if data['data']['rooms']:
				return data['data']['rooms']
			else:
				self.handleerror("No Rooms")
				return 0

	def getschedule(self, room):
		# Function to return a list of scheduled recordings for the specified room.
		# Returns a list of schedules if successful. Each list item is actually a list containing information about that schedule.
		# Returns 0 on failure.
		# Returns an empty list if no schedules exist for the specified room.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'schedule?access_token=' + self.accesstoken
			roomsched = []
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					pass
			if data['data']['schedules']:
				for schedule in data['data']['schedules']:
					if schedule['room']['id'] == int(room):
						templist = []
						templist.append(schedule['start_at'])
						templist.append(schedule['stop_at'])
						templist.append(schedule['name'])
						roomsched.append(templist)
				roomsched.sort()
				if roomsched:
					if self.errormsg == "No Schedules Currently Set Up":
						self.errormsg = None
					return roomsched
				else:
					self.handleerror("No Schedules")
					return 0
			else:
				self.handleerror("No Schedules")
				return 0

	def getroomname(self, room):
		# Function to return the name of the specified room.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'rooms/info/' + str(room) + '?access_token=' + self.accesstoken

			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					# print data
					return data['data']['name']

	def getusername(self, user):
		# Function to return the name of the specified room.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'admin/users/' + str(user) + '?access_token=' + self.accesstoken

			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					# print data
					return data['data']['name']

	def getroomstatus(self, room):
		# Function to return the current state of the specified room.
		# Returns 0 on failure.
		# Returns 1 if the room is available.
		# Returns 2 if the room is recording.
		# Returns 3 if the room is paused.
		# Returns 4 if the room is locked.
		# Returns 5 if the room is prepared.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		# elif not isinstance(room, int):
		# 	self.handleerror("Invalid Room ID")
		# 	return 0
		else:
			url = self.baseurl + 'rooms/' + str(room) + '/status?access_token=' + self.accesstoken
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
					# print data
					if data['data']['status'] == 'available':
						return 1
					elif data['data']['status'] == 'recording':
						return 2
					elif data['data']['status'] == 'paused':
						return 3
					elif data['data']['status'] == 'locked':
						return 4
					elif data['data']['status'] == 'prepared':
						return 5
					else:
						self.handleerror("Unknown Status")
						return 0
				except:
					self.handleerror("Invalid Room ID")
					return 0
				else:
					pass

	def getusers(self):
		# Function to return a list of users.
		# Returns 0 on failure.
		# Each list item is a dictionary with information about the user.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'admin/users?access_token=' + self.accesstoken
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					if data['data']:
						return data['data']
					else:
						self.handleerror("No Users")
						return 0

	def setsharing(self, recid, **kwargs):
		# Function changes sets sharing permission on the specified recording.
		# Users and groups must be passed as lists, encloded in [].
		# Returns 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			if 'users' in kwargs and 'groups' in kwargs:
				values = {"share": {"users": kwargs['users'], "groups": kwargs['groups']}}
			elif 'users' in kwargs:
				values = {"share": {"users": kwargs['users']}}
			elif 'groups' in kwargs:
				values = {"share": {"groups": kwargs['groups']}}
			else:
				self.handleerror("No Users or Groups Specified")
				return 0
			# print(values)
			url = self.baseurl + 'records/' + str(recid) + '/update?access_token=' + self.accesstoken
			params = json.dumps(values).encode('utf-8')
			# print(url)
			try:
				req = urllib.request.Request(url)
				req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				self.logger.info(__name__ + ": " + "Sharing Permissions Updated")
				self.logger.debug(__name__ + ": " + str(values))
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					# print data
					return data['data']['id']

	def lockroom(self, room):
		# Function locks the specified room.
		# Returns 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		if self.getroomstatus(room) == 1 or self.getroomstatus(room) == 5:
			url = self.baseurl + 'rooms/' + str(room) + '/lock' + '?access_token=' + self.accesstoken
			values = {"nothing": "nothing"}
			params = json.dumps(values).encode('utf-8')
			try:
				req = urllib.request.Request(url)
				req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				self.logger.info(__name__ + ": " + str(self.getroomname(room)) + " Locked")
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					return data['data']['id']
		else:
			self.handleerror("No Lock")
			return 0

	def unlockroom(self, room):
		# Function unlocks the specified room.
		# Returns 0 on failure.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		if self.islocked(room):
			url = self.baseurl + 'rooms/' + str(room) + '/unlock' + '?access_token=' + self.accesstoken
			values = {"nothing": "nothing"}
			params = json.dumps(values).encode('utf-8')
			try:
				req = urllib.request.Request(url)
				req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				self.logger.info(__name__ + ": " + str(self.getroomname(room)) + " Unlocked")
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					return data['data']['id']
		else:
			self.handleerror("Not Locked")
			return 0

	def handleerror(self, e):
		self.logger.error(__name__ + ": " + str(e))
		if str(e) == "<urlopen error timed out>" or str(e) == "<urlopen error [Errno 11001] getaddrinfo failed>" or str(e) == "HTTP Error 400: Bad Request" or str(e) == "<urlopen error [Errno -3] Temporary failure in name resolution>" or str(e) == "<urlopen error [WinError 10061] No connection could be made because the target machine actively refused it>" or str(e) == "<urlopen error _ssl.c:989: The handshake operation timed out>":
			self.errormsg = "Server Address Unreachable"
			self.accesstoken = 0
			self.reauthenticate(self.failure_reauth_time)
		elif str(e) == "timed out" or str(e) == "Remote end closed connection without response" or str(e) == "The read operation timed out":
			self.errormsg = "Server Did Not Respond"
			self.accesstoken = 0
			self.reauthenticate(self.failure_reauth_time)
		elif str(e) == "HTTP Error 401: Unauthorized":
			self.errormsg = "Invalid Username or Password"
			self.accesstoken = 0
			self.reauthenticate(self.failure_reauth_time)
		elif str(e) == "HTTP Error 404: Not Found":
			if self.accesstoken != 0:
				self.errormsg = "Invalid Room, User, or Recording ID"
			else:
				self.errormsg = "Unable to Connect to VALT Server"
				self.reauthenticate(self.failure_reauth_time)
		elif str(e) == "HTTP Error 502: Bad Gateway":
			self.errormsg = "VALT Server Offline"
			self.accesstoken = 0
			self.reauthenticate(self.failure_reauth_time)
		elif str(e) == "No Recording":
			self.errormsg = "Room is Not Currently Recording"
		elif str(e) == "Room Already Recording":
			self.errormsg = "Unable to Start Recording in a Room that is Already Recording"
		elif str(e) == "Room Paused":
			self.errormsg = "Room is Currently Paused"
		elif str(e) == "Room Not Paused":
			self.errormsg = "Room is Not Currently Paused"
		elif str(e) == "No Cameras":
			self.errormsg = "No Cameras in Room"
		elif str(e) == "No Rooms":
			self.errormsg = "No Rooms Currently Set Up"
		elif str(e) == "No Schedules":
			self.errormsg = "No Schedules Currently Set Up"
		elif str(e) == "Unknown Status":
			self.errormsg = "Room Status Unknown"
		elif str(e) == "No Users":
			self.errormsg = "No Users Currently Set Up"
		elif str(e) == "Not Locked":
			self.errormsg = "Room Not Currently Locked"
		elif str(e) == "No Lock":
			self.errormsg = "Room Cannot Be Locked"
		elif str(e) == "Invalid Room ID":
			self.errormsg = "Invalid Room ID"
		else:
			self.errormsg = "An Unknown Error Occurred"
			self.accesstoken = 0
			self.reauthenticate(self.failure_reauth_time)
	def reauthenticate(self, reauthtime):
		self.logger.info(__name__ + ":" + " Next authentication attempt in " + str(reauthtime) + " seconds")
		if hasattr(self, 'reauth'):
			self.reauth.cancel()
		self.reauth = threading.Timer(reauthtime, self.auth)
		self.reauth.daemon = True
		self.reauth.start()

	def changeserver(self, valt_address, valt_username, valt_password):
		if valt_address != "None" and valt_address != "" and valt_address is not None:
			if valt_address.find("http", 0, 4) == -1:
				self.baseurl = 'http://' + valt_address + '/api/v3/'
			else:
				self.baseurl = valt_address + '/api/v3/'
		else:
			self.baseurl = None
		self.username = valt_username
		self.password = valt_password
		self.auth()

	def testconnection(self, valt_address, valt_username, valt_password):
		values = {"username": valt_username, "password": valt_password}
		params = json.dumps(values).encode('utf-8')
		if valt_address.find("http", 0, 4) == -1:
			valt_baseurl = 'http://' + valt_address + '/api/v3/'
		else:
			valt_baseurl = valt_address + '/api/v3/'
		self.logger.debug(__name__ + ": " + "Testing Connection to VALT server")
		self.logger.debug(__name__ + ": " + valt_baseurl)
		self.logger.debug(__name__ + ": " + valt_username)
		self.logger.debug(__name__ + ": " + valt_password)

		try:
			req = urllib.request.Request(valt_baseurl + 'login')
			req.add_header('Content-Type', 'application/json')
			response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
		except urllib.error.HTTPError as e:
			self.logger.warning(__name__ + ": " + str(e))
			if str(e) == "HTTP Error 401: Unauthorized":
				self.testmsg = "Invalid Username or Password"
			return False
		except urllib.error.URLError as e:
			self.logger.warning(__name__ + ": " + str(e))
			self.testmsg = "Unable to Connect"
			return False
		except http.client.HTTPException as e:
			self.logger.warning(__name__ + ": " + str(e))
			self.testmsg = "Unable to Connect"
			return False
		except Exception as e:
			self.logger.warning(__name__ + ": " + str(e))
			self.testmsg = "Unable to Connect"
			return False
		else:
			return True

	def getrecords(self, **kwargs):
		# Function to return a list of records.
		# Returns 0 on failure.
		# Each list item is a dictionary with information about the user.
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			if 'search' in kwargs and 'start_date' in kwargs:
				values = {"search": kwargs['search'], "start_date": kwargs['start_date']}
			elif 'search' in kwargs:
				values = {"search": kwargs['search']}
			elif 'start_date' in kwargs:
				values = {"start_date": kwargs['start_date']}
			else:
				self.handleerror("No Search Criteria Specified")
				return 0
			url = self.baseurl + 'records?access_token=' + self.accesstoken
			# values = {"search" : searchstring}
			params = json.dumps(values).encode('utf-8')
			try:
				req = urllib.request.Request(url)
				req.add_header('Content-Type', 'application/json')
				print(url)
				print(params)
				response = urllib.request.urlopen(req, params, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					if data['data']:
						return data['data']
					else:
						self.handleerror("No Records")
						return 0
	def getversion(self):
		# Function to get the current active recording id in the specified room
		# Returns true if the specified room is recording
		# Returns False if the room is not recording
		# Returns 2 if an error is encountered
		# Returns 99 if not currently authenticated to VALT
		if self.accesstoken == 0:
			return 99
		else:
			url = self.baseurl + 'admin/general?access_token=' + self.accesstoken
			try:
				req = urllib.request.Request(url)
				# req.add_header('Content-Type', 'application/json')
				response = urllib.request.urlopen(req, timeout=self.httptimeout)
			except urllib.error.HTTPError as e:
				self.handleerror(e)
				return 0
			except urllib.error.URLError as e:
				self.handleerror(e)
				return 0
			except http.client.HTTPException as e:
				self.handleerror(e)
				return 0
			except Exception as e:
				self.handleerror(e)
				return 0
			else:
				try:
					data = json.load(response)
				except Exception as e:
					self.handleerror(e)
					return 0
				else:
					# print data
					if "version" in data['data'].keys():
						return data['data']['version']
					else:
						self.handleerror("No Version")
						return 0

	def check_room_status(self):
		while not self.kill_threads:
			self.logger.debug(__name__ + ": " + "Room Check Loop: " + str(self.run_check_room_status))
			if self.run_check_room_status:
				self.logger.debug(__name__ + ": " + "Room Check Loop: " + "Access Token: " + str(self.accesstoken))
				if self.accesstoken != 0 and self.selected_room != None:
					temp_room_status = self.getroomstatus(self.selected_room)
					if temp_room_status != self.selected_room_status:
						self.selected_room_status = temp_room_status
					if temp_room_status != 0 and temp_room_status != 99 and self.errormsg != None:
						print("Clear Error")
						self.errormsg = None
						self.selected_room_status = temp_room_status
					self.logger.debug(__name__ + ": " + "Checking Room " + str(self.selected_room) + " current status is " + str(self.selected_room_status))
			time.sleep(self.room_check_interval)

	def start_room_check_thread(self):
		self.kill_threads = False
		self.run_check_room_status = True
		self.logger.debug(__name__ + ": " + "Room Check Thread Started")
		if not hasattr(self,'room_check_thread'):
			self.room_check_thread = threading.Thread(target=self.check_room_status)
			self.room_check_thread.daemon = True
			self.room_check_thread.start()

	def stop_room_check_thread(self):
		self.run_check_room_status = False
	@property
	def selected_room_status(self):
		return self._selected_room_status
	@selected_room_status.setter
	def selected_room_status(self,new_status):
		self._selected_room_status = new_status
		for callback in self._observers:
			callback(self._selected_room_status)
		self.logger.debug(__name__ + ": " + str(self.selected_room) + ' status updated to ' + str(new_status))
	def bind_to_selected_room_status(self,callback):
		self._observers.append(callback)
	def unbind_to_selected_room_status(self,callback):
		self._observers.remove(callback)
	@property
	def errormsg(self):
		return self._errormsg
	@errormsg.setter
	def errormsg(self,newmsg):
		self._errormsg = newmsg
		for callback in self._errormsg_observers:
			callback(self._errormsg)
	def bind_to_errormg(self,callback):
		self._errormsg_observers.append(callback)
	def disconnect(self):
		self.kill_threads = True

	def change_timeout(self,new_timeout):
		self.logger.info(__name__ + ": " + "HTTP Timeout set to " + str(new_timeout))
		self.httptimeout = int(new_timeout)

