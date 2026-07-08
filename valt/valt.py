from .mixins.admin import ValtAdmin
from .mixins.admin_templates import ValtAdminTemplates
from .mixins.audio import ValtAudio
from .mixins.comment import ValtComment
from .mixins.communication import ValtCommunication
from .mixins.download import ValtDownload
from .mixins.errors import ValtErrors
from .mixins.filters import ValtFilters
from .mixins.groups import ValtGroups
from .mixins.help import ValtHelp
from .mixins.log import ValtLog
from .mixins.monitor import ValtMonitor
from .mixins.preset import ValtPreset
from .mixins.records import ValtRecords
from .mixins.recording import ValtRecording
from .mixins.rights import ValtRights
from .mixins.room import ValtRoom
from .mixins.schedule import ValtSchedule
from .mixins.template import ValtTemplate
from .mixins.upload import ValtUpload
from .mixins.users import ValtUsers
from .mixins.auth import ValtAuth

class VALT(ValtCommunication,ValtLog,ValtRecording,ValtUpload,ValtDownload,ValtRoom,ValtPreset,ValtUsers,ValtGroups,ValtComment,ValtAdmin,ValtAdminTemplates,ValtTemplate,ValtAudio,ValtRights,ValtRecords,ValtFilters,ValtSchedule,ValtHelp,ValtErrors,ValtAuth,ValtMonitor):
	def __init__(self, valt_address, valt_username, valt_password, timeout=5,logpath="ivs.log", **kwargs):
		super().__init__(logpath=logpath)
		if valt_address != "None" and valt_address != "" and valt_address is not None:
			if valt_address.find("http", 0, 4) == -1:
				self.baseurl = 'http://' + valt_address + '/api/v3/'
			else:
				self.baseurl = valt_address + '/api/v3/'
		else:
			self.baseurl = None
		self.username = valt_username
		self.password = valt_password
		self.success_reauth_time = 28800
		self.failure_reauth_time = 30
		self._errormsg_observers = []
		self._errormsg = None
		self._accesstoken = 0
		self._accesstoken_observers = []
		self.httptimeout = int(timeout)
		self.kill_threads = False
		self._selected_room_status = 99
		self.run_check_room_status = False
		self._observers = []
		self.auth()

		if 'room' in kwargs:
			try:
				self.selected_room = int(kwargs['room'])
			except (ValueError, TypeError):
				self.selected_room = None
		else:
			self.selected_room = None

		if 'room_check_interval' in kwargs:
			self.room_check_interval = int(kwargs['room_check_interval'])
		else:
			self.room_check_interval = 5

		self.start_room_check_thread()

	def disconnect(self):
		self.kill_threads = True
		if hasattr(self, 'reauth'):
			self.reauth.cancel()

	def change_timeout(self,new_timeout):
		self.logger.info(__name__ + ": " + "HTTP Timeout set to " + str(new_timeout))
		self.httptimeout = int(new_timeout)



