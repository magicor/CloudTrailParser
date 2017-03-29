#!/usr/bin/env python

#from datetime import datetime
import datetime
import gzip
import json
import os
import re
#import ExportToHTML

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
			#'account_id': str(source['recipientAccountId']),
			#'region': str(source['awsRegion']),
			'event_name': str(source['eventName']),
			'event_time': event_time_utc,
			'event_source': str(source['eventSource']),
			'source_ip': str(source['sourceIPAddress']),
			'user_type': UserType,
			'user_name': UserName,
			'user_arn': UserARN,
			'invoked_by': InvokedBy,
			'request': self.strip_data_unicode(source['requestParameters']),
			'response': self.strip_data_unicode(source['responseElements'])
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

class ExportToHTML:

	def createHTML(self, myFile):
		html_script = """
	<!DOCTYPE html>
	<html>
	<head>
	    <meta charset="utf-8">
	    <title>CloudTrailLog Parser</title>"""
		
		Html_file=open(myFile,"w")
		Html_file.write(html_script)
		Html_file.close()


	def addScript(self, myFile):
		html_script="""
	    <!-- jQuery -->
	    <script src="js/jquery-latest.min.js"></script>
	    <script src="js/jquery-ui.min.js"></script>

	    <!-- Demo stuff -->
	    <link rel="stylesheet" href="css/jq.css">
	    <link href="css/prettify.css" rel="stylesheet">
	    <link rel="stylesheet" href="css/magnific-popup.css">
	    <link rel="stylesheet" href="css/jquery-ui.min.css">
	    <script src="js/prettify.js"></script>
	    <script src="js/docs.js"></script>
	    <script src="js/jquery.magnific-popup.min.js"></script>

	    <!-- Tablesorter: theme -->
	    <link class="theme default" rel="stylesheet" href="css/theme.default.css">
	    <link class="theme blue" rel="stylesheet" href="css/theme.blue.css">
	    <link class="theme green" rel="stylesheet" href="css/theme.green.css">
	    <link class="theme grey" rel="stylesheet" href="css/theme.grey.css">
	    <link class="theme ice" rel="stylesheet" href="css/theme.ice.css">
	    <link class="theme black-ice" rel="stylesheet" href="css/theme.black-ice.css">
	    <link class="theme dark" rel="stylesheet" href="css/theme.dark.css">
	    <link class="theme dropbox" rel="stylesheet" href="css/theme.dropbox.css">
	    <link class="theme metro-dark" rel="stylesheet" href="css/theme.metro-dark.css">

	    <style id="css">/* wrapper of table 2 */
	.wrapper {
	    position: relative;
	    padding: 0 5px;
	    height: 250px;
	    overflow-y: auto;
	}

	/* Magnific popup */
	#popup {
	    position: relative;
	    background: #FFF;
	    padding: 20px;
	    width: auto;
	    max-width: 500px;
	    margin: 20px auto;
	}
	/* Since the popup has a 20px margin, we need to adjust the wrapper position
	Note:
	 this is only required because we aren't actually attaching the sticky header
	 to the #popup, instead we're attaching it to the .mfp-wrap because that
	 element scrolls instead of the window
	*/
	#popup .tablesorter-sticky-wrapper {
	    margin-left: 20px;
	    margin-top: -20px;
	}</style>

	    <!-- Tablesorter script: required -->
	    <script src="js/jquery.tablesorter.js"></script>
	    <script src="js/widget-filter.js"></script>
	    <script src="js/widget-stickyHeaders.js"></script>

	    <script id="js">$(function(){

	    $('.open-popup-link').magnificPopup({
	        type: 'inline',
	        midClick: true,
	        callbacks: {
	            open: function () {
	                // Will fire when this exact popup is opened
	                // this - is Magnific Popup object
	                $('#table0').tablesorter({
	                    theme: 'blue',
	                    headerTemplate : '{content} {icon}', // Add icon for various themes
	                    widgets: ['zebra', 'filter', 'stickyHeaders'],
	                    widgetOptions: {
	                        // jQuery selector or object to attach sticky header to
	                        stickyHeaders_attachTo: '.mfp-wrap',
	                        stickyHeaders_offset: 0,
	                        // caption set by demo button value
	                        stickyHeaders_includeCaption: includeCaption
	                    }
	                });
	            }
	        }
	    });

	    $('#table1, .nested, #table3').tablesorter({
	        widthFixed : true,
	        showProcessing: true,
	        headerTemplate : '{content} {icon}', // Add icon for various themes

	        widgets: [ 'zebra', 'stickyHeaders', 'filter' ],

	        widgetOptions: {

	            // extra class name added to the sticky header row
	            stickyHeaders : '',
	            // number or jquery selector targeting the position:fixed element
	            stickyHeaders_offset : 0,
	            // added to table ID, if it exists
	            stickyHeaders_cloneId : '-sticky',
	            // trigger "resize" event on headers
	            stickyHeaders_addResizeEvent : true,
	            // if false and a caption exist, it won't be included in the sticky header
	            stickyHeaders_includeCaption : true,
	            // The zIndex of the stickyHeaders, allows the user to adjust this to their needs
	            stickyHeaders_zIndex : 2,
	            // jQuery selector or object to attach sticky header to
	            stickyHeaders_attachTo : null,
	            // jQuery selector or object to monitor horizontal scroll position (defaults: xScroll > attachTo > window)
	            stickyHeaders_xScroll : null,
	            // jQuery selector or object to monitor vertical scroll position (defaults: yScroll > attachTo > window)
	            stickyHeaders_yScroll : null,

	            // scroll table top into view after filtering
	            stickyHeaders_filteredToTop: true

	            // *** REMOVED jQuery UI theme due to adding an accordion on this demo page ***
	            // adding zebra striping, using content and default styles - the ui css removes the background from default
	            // even and odd class names included for this demo to allow switching themes
	            // , zebra   : ["ui-widget-content even", "ui-state-default odd"]
	            // use uitheme widget to apply defauly jquery ui (jui) class names
	            // see the uitheme demo for more details on how to change the class names
	            // , uitheme : 'jui'
	        }
	    });

	    /* make second table scroll within its wrapper */
	    $('#table2').tablesorter({
	        widthFixed : true,
	        headerTemplate : '{content} {icon}', // Add icon for various themes

	        widgets: [ 'zebra', 'stickyHeaders', 'filter' ],

	        widgetOptions: {
	            // jQuery selector or object to attach sticky header to
	            stickyHeaders_attachTo : '.wrapper' // or $('.wrapper')
	        }
	    });

	});</script>
	<script>
	$(function() {

	    window.includeCaption = true;
	    $('.caption').on('click', function(){
	        includeCaption = !includeCaption;
	        $(this).html( '' + includeCaption );
	        $('#table0, #table1, #table2, #table3, .nested').each(function(){
	            if (this.config) {
	                this.config.widgetOptions.stickyHeaders_includeCaption = includeCaption;
	                this.config.widgetOptions.$sticky.children('caption').toggle(includeCaption);
	            }
	        });
	    });

	    // removed jQuery UI theme because of the accordion!
	    $('link.theme').each(function(){ this.disabled = true; });

	    var themes = 'blue default green grey ice black-ice dark dropbox metro-dark',
	        i, o = '', t = themes.split(' ');
	    for (i = 0; i < t.length; i++) {
	        o += '<option value="' + t[i] + '">' + t[i] + '</option>';
	    }

	    $('select:first')
	        .append(o)
	        .change(function(){
	            var theme = $(this).val().toLowerCase(),
	                // ui-theme is added by the themeswitcher
	                files = $('link.theme').each(function(){
	                    this.disabled = true;
	                })
	            files.filter('.' + theme).each(function(){
	                this.disabled = false;
	            });
	            $('table')
	                .removeClass('tablesorter-' + t.join(' tablesorter-'))
	                .addClass('tablesorter-' + (theme === 'black-ice' ? 'blackice' : theme) );
	        }).change();

	    $('input[type="checkbox"]').click(function() {
	        var index = $(this).attr('name').substr(3);
	        index--;
	        $('table tr').each(function() { 
	            $('td:eq(' + index + ')',this).toggle();
	        });
	        $('th.' + $(this).attr('name')).toggle();
	    });

	});
	</script>"""

		Html_file=open(myFile,"a")
		Html_file.write(html_script)
		Html_file.close()


	def addHeader(self, myFile):
		html_header = """
	</head>
	<body>

	<div id="banner">
	    <h1>CloudTrail Log<em>Parser</em></h1>
	    <h2>Human Friendly Formater</h2>
	    <h3>Understand your log</h3>
	</div>

	<div id="main">

	    <p></p>
	    <br>

	    <div id="root" class="accordion">

	        <h3><a href="#">Notes</a></h3>
	        <div>
	            <h4>This tool is used for CloudTrail log analysis. Change its JSON format to a readable table format.</h4>
	        </div>
	    </div>
	    </br>
	    Choose Theme:
	    <select></select>
	    <p></p>

	    <h3>Select headers to display:</h3>
	    <form>
	        <div id="checkbox"><input type="checkbox" name="col1" checked="checked" /> Event Time </div>
	        <div id="checkbox"><input type="checkbox" name="col2" checked="checked" /> Event Name </div>
	        <div id="checkbox"><input type="checkbox" name="col3" checked="checked" /> Event Source </div>
	        <div id="checkbox"><input type="checkbox" name="col4" checked="checked" /> Source IP </div>
	        <div id="checkbox"><input type="checkbox" name="col5" checked="checked" /> User Type </div>
	        <div id="checkbox"><input type="checkbox" name="col6" checked="checked" /> User Name </div>
	        <div id="checkbox"><input type="checkbox" name="col7" checked="checked" /> Invoked By </div>
	        <div id="checkbox"><input type="checkbox" name="col8" checked="checked" /> Request Elements </div>
	        <div id="checkbox"><input type="checkbox" name="col9" checked="checked" /> Response Elements </div>
	    </form>
	    <table id="table1" class="tablesorter">
	    <thead>
	            <tr>
	            <th  class="col1" data-placeholder="filter">Event Time</th>
	            <th  class="col2" data-placeholder="filter">Event Name</th>
	            <th  class="col3" data-placeholder="filter">Event Source</th>
	            <th  class="col4" data-placeholder="filter">Source IP</th>
	            <th  class="col5" data-placeholder="filter">User Type</th>
	            <th  class="col6" data-placeholder="filter">User Name</th>
	            <th  class="col7" data-placeholder="filter">Invoked By</th>
	            <th  class="col8" data-placeholder="filter">Request Elements</th>
	            <th  class="col9" filter-false sorter-false">Response Elements</th>
	        </thead>
	    <tfoot>
	        <tr><th>Event Time</th><th>Event Name</th><th>Event Source</th><th>Source IP</th><th>User Type</th><th>User Name</th><th>Invoked By</th><th>Request Elements</th><th>Response Elements</th></tr>
	    </tfoot>
	    <tbody>
	"""

		Html_file=open(myFile,"a")
		Html_file.write(html_header)
		Html_file.close()

	def addCheckbox(self, myFile, row):
		
		Html_file=open(myFile,"a")
		Html_file.write(html_header)
		Html_file.close()

	def addRow(self, myFile, row):
		Html_file=open(myFile,"a")
		Html_file.write(row)
		Html_file.close()

	def addEnd(self, myFile):
		html_end = """
		</tbody>
	    </table>
	</div>
	</body>
	</html>"""

		Html_file=open(myFile,"a")
		Html_file.write(html_end)
		Html_file.close()

	def export(self, myFile, myParser):
		self.createHTML(myFile)
		self.addScript(myFile)
		self.addHeader(myFile)
		for event in myParser.events():
			aRow = "\t\t<tr><td>"+str(event['event_time'])[:-6]+"</td><td>"+str(event['event_name'])+"</td><td>"+str(event['event_source'])+"</td><td>"+str(event['source_ip'])+"</td><td>"+str(event['user_type'])+"</td><td>"+str(event['user_name'])+"</td><td>"+str(event['invoked_by'])+"</td><td>"+str(event['request'])+"</td><td>"+str(event['response'])+"</td></tr>\n"
			self.addRow(myFile,aRow)

		self.addEnd(myFile)

def main():
	parser = Parser('/Users/dongj/Desktop/CloudTrailLog')
	filename = 'test.html'
	myExport = ExportToHTML()
	myExport.export(filename, parser)

if (__name__ == '__main__'):
	main()