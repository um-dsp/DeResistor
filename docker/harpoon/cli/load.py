#!/usr/bin/env python

#
# $Id: load.py,v 1.2 2004-05-31 18:30:15 jsommers Exp $
#

import sys,xmlrpclib
from getopt import *

def usage(proggie):
        print "usage: ", proggie, "[-u <url>]* [plugin_name]"
        exit

try:
        opts,args = getopt(sys.argv[1:], "u:", [])
except GetoptError,e:
        print "exception while processing options: ", e
        usage (sys.argv[0])


url_list = []
for o, a in opts:
        if o == "-u":
                url_list.append(a)

for server_url in url_list:
	server = xmlrpclib.ServerProxy(server_url)
	for config in args:
		print "loading " + config + " config file on ",server_url
		try:
			result = server.loadConfig(config)
			print "result: ", result
		except sys.exc_info, einfo:
			print "ERROR", einfo[exc_value]
