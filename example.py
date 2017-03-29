#!/usr/bin/env python

import cloudtrailparser
import ExportToHTML


def main():
	parser = cloudtrailparser.Parser('/Users/dongj/Desktop/CloudTrailLog')
	filename = 'test.html'
	ExportToHTML.export(filename, parser)

if (__name__ == '__main__'):
	main()
