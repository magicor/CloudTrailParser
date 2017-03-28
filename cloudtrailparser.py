#from datetime import datetime
import datetime
import gzip
import json
import os
import re

#import timezone

class BaseTimezone(datetime.tzinfo):
        TIMEDELTA_ZERO = datetime.timedelta(0)

        def __init__(self,timezone_name,offset_seconds):
                datetime.tzinfo.__init__(self)

                self.timezone_name = timezone_name
                self.offset = datetime.timedelta(seconds = offset_seconds)

        def utcoffset(self,dt):
                return self.offset

        def dst(self,dt):
                return BaseTimezone.TIMEDELTA_ZERO

        def tzname(self,dt):
                return self.timezone_name

# define timezones
class UTC(BaseTimezone):
        def __init__(self):
                BaseTimezone.__init__(self,'UTC',0)

class Melbourne(BaseTimezone):
        def __init__(self):
                BaseTimezone.__init__(self,'Melbourne',10 * 3600)

class Parser:
	ARCHIVE_FILENAME_REGEXP = re.compile(r'^[0-9]{12}_CloudTrail_[a-z]{2}-[a-z]+-[0-9]_[0-9]{8}T[0-9]{4}Z_[a-zA-Z0-9]{16}\.json')
	CLOUDTRAIL_EVENT_DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
	#TIMEZONE_UTC = timezone.UTC()
	TIMEZONE_UTC = UTC()

	def __init__(self,archive_base_dir):
		# store base dir to CloudTrail archives
		self.archive_base_dir = archive_base_dir.rstrip('/')
		
	def events(self):
		# work over CloudTrail archive files
		for archive_file_item in self.archive_file_list():
			if archive_file_item.endswith('.gz'):
				# open archive - parse JSON contents to dictionary
				fp = gzip.open(archive_file_item,'rb')
				#print('Read in gz file ...')
			elif archive_file_item.endswith('.json'):
				fp = open(archive_file_item)
				#print('Read in JSON file ...')
			cloudtrail_data = json.loads(fp.read())
			fp.close()

			if ('Records' in cloudtrail_data):
				for trail_item in cloudtrail_data['Records']:
					yield self.build_trail_data(trail_item)

	def archive_file_list(self):
		for base_path, dir_list, file_list in os.walk(self.archive_base_dir):
			# work over files in directory
			for file_item in file_list:
				# does file item match archive pattern?
				if (not Parser.ARCHIVE_FILENAME_REGEXP.search(file_item)):
					# nope - skip file
					continue

				# full path to archive file
				yield '{0}/{1}'.format(base_path,file_item)

	def build_trail_data(self,source):
		# convert time string to datetime at UTC
		event_time_utc = (
			datetime.datetime.strptime(
				source['eventTime'],
				Parser.CLOUDTRAIL_EVENT_DATETIME_FORMAT
			)
			.replace(tzinfo = Parser.TIMEZONE_UTC)
		)

		# extract the data we care about from the CloudTrail item into dict
		#print(self.strip_data_unicode(source['userIdentity']))
		UserType = str(source['userIdentity']['type'])
		if 'arn' in source['userIdentity']:
			UserARN = str(source['userIdentity']['arn'])
		else:
			UserARN = 'null'
		if 'userName' in source['userIdentity']:
			UserName = str(source['userIdentity']['userName'])
		else:
			UserName = 'null'
		if 'invokedBy' in source['userIdentity']:
			InvokedBy = str(source['userIdentity']['invokedBy'])
		else:
			InvokedBy = 'null'

		return {
			'account_id': str(source['recipientAccountId']),
			'region': str(source['awsRegion']),
			'event_name': str(source['eventName']),
			'event_time': event_time_utc,
			'event_source': str(source['eventSource']),
			'source_ip': str(source['sourceIPAddress']),
			'request': self.strip_data_unicode(source['requestParameters']),
			'response': self.strip_data_unicode(source['responseElements']),
			'user_type': UserType,
			'user_name': UserName,
			'user_arn': UserARN,
			'invoked_by': InvokedBy
		}

	def strip_data_unicode(self,data):
		data_type = type(data)

		# recursively process via strip_data_unicode() both list and dictionary structures
		if (data_type is list):
			return [
				self.strip_data_unicode(list_item)
				for list_item in data
			]

		if (data_type is dict):
			return {
				self.strip_data_unicode(dict_key): self.strip_data_unicode(dict_value)
				for (dict_key,dict_value) in data.items()
			}

		# simple value
		if (data_type is unicode):
			# if unicode cast to string
			data = str(data)

		return data
