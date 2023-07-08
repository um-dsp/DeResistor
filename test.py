#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Feb  3 19:20:58 2023

@author: abderrahmen

This script can be used only for real-world tests (e.g. against GFW)
"""

import os, sys
import signal
import engine
import subprocess
import time
import argparse

# Port to run the engine on
port = 80

### Edit to add strategies to test ###
strategies = ['\/','[TCP:flags:PA]-duplicate(tamper{TCP:dataofs:replace:10}(tamper{TCP:chksum:corrupt},),)-|']

cmd = sys.argv[1:]
parser = argparse.ArgumentParser(description='Computing the success rate of a list of strategies', add_help=False, prog="test.py")
parser.add_argument('--country', action='store', choices=['China','India','Kazakhstan'], default="China", help="Country to test strategies in")
#parser.add_argument('--strategies', action='store', default="'\/'", help="list of strategies to test")
parser.add_argument('--runs', action='store', type=int, default=30, help='Number of tests for each strategies')

if not cmd:
    parser.error("No arguments specified")

args, _ = parser.parse_known_args(cmd)  
args = vars(args)
#print(args)
country = args['country']
runs = args['runs']

print('Running {} in {} {} times'.format(strategies,country,runs))

def exec_cmd_output(command, timeout=60):
    
    output = ""
    
    try:
        p = subprocess.Popen(cmd, start_new_session=True,shell=True,stdout=subprocess.PIPE)
        p.wait(timeout=timeout)
        output, err = p.communicate()
        output = output.decode('utf-8', 'ignore')
    except subprocess.TimeoutExpired as tmer:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        print('Timeout expired')
        output='error'
    except subprocess.CalledProcessError as exc:
        output='error'
    return output
    

sport=6350
success={}
errors ={}

for strategy in strategies:
    success[strategy]=0
    errors[strategy]=0
    for run in range(runs):
        os.system('sudo iptables -F')
        # Create the engine in debug mode
        with engine.Engine(port, strategy, log_level="debug") as eng:
            
            if country == 'Kazakhstan':
                cmd = "curl -L --no-keepalive --local-port "+str(sport)+" --connect-to ::93.184.216.34: 'http://youporn.com' -D -"
            elif country == 'China':
                cmd = "curl -L --no-keepalive --local-port "+str(sport)+" --connect-to ::23.185.0.2: 'http://hrw.org' -D -"
            elif country == 'India':
                cmd = "curl -L --no-keepalive --local-port "+str(sport)+" http://www.bannedthought.net"
            out = exec_cmd_output(cmd)
            time.sleep(5)
            if out != 'error':
                print('\n Output for run {} is {}.\n\n'.format(run,out))
                
                #if out.find('400 Bad request') == -1 and out != '<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0"/><style>body{margin:0px;padding:0px;}iframe{width:100%;height:100%}</style><iframe src="http://14.141.123.218:8080/webadmin/deny/index.php?dpid=9&dpruleid=4&cat=107&dplanguage=-&url=http%3a%2f%2fwww%2exnxx%2ecom%2f" width="100%" height="100%" frameborder=0></iframe>':
                #if out.find('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">') != -1 or out.find('Moved Permanently') != -1:
                if out.find('<!DOCTYPE html') != -1 or out.find('404 Not Found')  != -1 or out.find('<!DOCTYPE HTML') != -1 or out.find('Pantheon') != -1:
                    success[strategy]+=1
            else:
                errors[strategy]+=1
        print('\n\n\n',success,'\n\n\n')
        if sport == 60000:
            sport=6002
        else:
            sport+=1
    #break
    #success[strategy]= success[strategy]
    with open('success_rate.txt', 'w') as the_file:
        the_file.write(strategy+' : '+str(success[strategy]/runs)+'\n')
    