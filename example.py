#!/usr/bin/env python

import cloudtrailparser
import ExportToHTML


def main():
	parser = cloudtrailparser.Parser('/Users/dongj/Desktop/CloudTrailLog')
	filename = 'test3.html'
	ExportToHTML.export(filename, parser)
	#ExportToHTML.createHTML(filename)
	#ExportToHTML.addScript(filename)
	#ExportToHTML.addHeader(filename)
	

	#template = "{0:28}|{1:32}|{2:38}|{3:30}|{4:12}|{5:12}|{6:20}" # column widths: 8, 10, 15, 7, 10
	#print "\033[1m" + template.format('Event Time', 'Event Name', 'Event Source', 'Source IP', 'User Type', 'User Name', 'Invoked By')
	#for event in parser.events():
	#	aRow = "\t\t<tr><td>"+str(event['event_time'])[:-6]+"</td><td>"+str(event['event_name'])+"</td><td>"+str(event['event_source'])+"</td><td>"+str(event['source_ip'])+"</td><td>"+str(event['user_type'])+"</td><td>"+str(event['user_name'])+"</td><td>"+str(event['invoked_by'])+"</td></tr>\n"
	#	ExportToHTML.addRow(filename,aRow)
		#print "\033[0m" + template.format(str(event['event_time']), str(event['event_name']), str(event['event_source']), str(event['source_ip']), str(event['user_type']), str(event['user_name']), str(event['invoked_by']))
		#print('Event name: {0}'.format(event['event_name']))
		#print('Event source: {0}'.format(event['event_source']))
		#print('Event time: {0}'.format(event['event_time']))
		#print('Source IP: {0}'.format(event['source_ip']))
		#print('User type: {0}'.format(event['user_type']))
		#print('User name: {0}'.format(event['user_name']))
		#print('Invoked by: {0}\n'.format(event['invoked_by']))
	
	#ExportToHTML.addEnd(filename)

if (__name__ == '__main__'):
	main()
