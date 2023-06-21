#!/usr/bin/env python

#
# $Id: stats.py,v 1.3 2005-03-07 19:41:02 jsommers Exp $
#

import sys,xmlrpc
from getopt import *

def usage(proggie):
        print("usage: ", proggie, "[-u <url>]*")
        exit

try:
        opts,args = getopt(sys.argv[1:], "u:", [])
except(GetoptError,e):
        print("exception while processing options: ", e)
        usage (sys.argv[0])


url_list = []
for o, a in opts:
        if o == "-u":
                url_list.append(a)

for server_url in url_list:
	server = xmlrpc.client.ServerProxy(server_url)
	print("stats for ",server)
	try:
		result = server.getStats()
		print(result)
	
	except(sys.exc_info, einfo):
		print("ERROR", einfo[exc_value])

