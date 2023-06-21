import copy
import datetime
import importlib
import inspect
import json
import logging
import os
import string
import sys
import random
import urllib.parse
import re
import socket
import random
import struct
import csv

import actions.action
import actions.trigger
import layers.packet
import plugins.plugin_client
import plugins.plugin_server

from scapy.all import TCP, IP, UDP, rdpcap
from scapy.utils import PcapReader
import netifaces


RUN_DIRECTORY = os.path.join("trials", datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S"))

# Hard coded options
FLAGFOLDER = "flags"

# Holds copy of console file handler's log level
CONSOLE_LOG_LEVEL = "debug"


BASEPATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASEPATH)


class SkipStrategyException(Exception):
    """
    Raised to signal that this strategy evaluation should be cut off.
    """
    def __init__(self, msg, fitness):
        """
        Creates the exception with the fitness to pass back
        """
        self.fitness = fitness
        self.msg = msg


def parse(requested_trees, logger):
    """
    Parses a string representation of a solution into its object form.
    """
    # First, strip off any hanging quotes at beginning/end of the strategy
    if requested_trees.startswith("\""):
        requested_trees = requested_trees[1:]
    if requested_trees.endswith("\""):
        requested_trees = requested_trees[:-1]

    # Define a blank strategy to initialize with the user specified string
    strat = actions.strategy.Strategy([], [])

    # Actions for the in and out forest are separated by a "\/".
    # Split the given string by this token
    out_in_actions = requested_trees.split("\\/")

    # Specify that we're starting with the out forest before we parse the in forest
    out = True
    direction = "out"
    # For each string representation of the action directions, in or out
    for str_actions in out_in_actions:
        # Individual action trees always end in "|" to signify the end - split the
        # entire action sequence into individual trees
        str_actions = str_actions.split("|")

        # For each string representation of each tree in the forest
        for str_action in str_actions:
            # If it's an empty action, skip it
            if not str_action.strip():
                continue

            assert " " not in str_action.strip(), "Strategy includes a space - malformed!"

            # Get rid of hanging whitespace from the splitting
            str_action = str_action.strip()

            # ActionTree uses the last "|" as a sanity check for well-formed
            # strategies, so restore the "|" that was lost from the split
            str_action = str_action + "|"
            new_tree = actions.tree.ActionTree(direction)
            success = new_tree.parse(str_action, logger)
            if success is False:
                raise actions.tree.ActionTreeParseError("Failed to parse tree")

            # Once all the actions are parsed, add this tree to the
            # current direction of actions
            if out:
                strat.out_actions.append(new_tree)
            else:
                strat.in_actions.append(new_tree)
        # Change the flag to tell it to parse the IN direction during the next loop iteration
        out = False
        direction = "in"
    return strat



def get_logger(basepath, log_dir, logger_name, log_name, environment_id, log_level="DEBUG", file_log_level="DEBUG", demo_mode=False):
    """
    Configures and returns a logger.
    """
    if type(log_level) == str:
        log_level = log_level.upper()
    if type(file_log_level) == str:
        file_log_level = file_log_level.upper()
    global CONSOLE_LOG_LEVEL
    full_path = os.path.join(basepath, log_dir, "logs")
    if not os.path.exists(full_path):
        os.makedirs(full_path)
    flag_path = os.path.join(basepath, log_dir, "flags")
    if not os.path.exists(flag_path):
        os.makedirs(flag_path)
    # Set up a client logger
    logger = logging.getLogger(logger_name + environment_id)
    logger.setLevel("DEBUG")
    # Disable the root logger to avoid double printing
    logger.propagate = False

    # If we've already setup the handlers for this logger, just return it
    if logger.handlers:
        return logger
    fh = logging.FileHandler(os.path.join(basepath, log_dir, "logs", "%s.%s.log" % (environment_id, log_name)))

    log_prefix = "[%s] " % log_name.upper()
    formatter = logging.Formatter("%(asctime)s %(levelname)s:" + log_prefix + "%(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_formatter = logging.Formatter(log_prefix + "%(asctime)s %(message)s")
    fh.setFormatter(file_formatter)
    logger.addHandler(fh)

    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    ch.setLevel(log_level)
    fh.setLevel(file_log_level)
    CONSOLE_LOG_LEVEL = log_level.lower()
    logger.addHandler(ch)
    return CustomAdapter(logger, {}) if demo_mode else logger

class CustomAdapter(logging.LoggerAdapter):
    """
    Used for demo mode, to change sensitive IP addresses where necessary. Can be used (mostly) like a regular logger.
    """
    regex = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

    def __init__(self, logger, extras):
        super().__init__(logger, extras)
        self.handlers = logger.handlers
        self.ips = {}
    
    def debug(self, msg, *args, **kwargs):
        """
        Print a debug message, uses logger.debug.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        """
        Print an info message, uses logger.info.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """
        Print a warning message, uses logger.warning.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """
        Print an error message, uses logger.error.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg, *args, **kwargs):
        """
        Print a critical message, uses logger.critical.
        """
        msg, args, kwargs = self.process(msg, args, kwargs)

        self.logger.critical(msg, *args, **kwargs)

    def get_ip(self, ip):
        """
        Lookup the assigned random IP for a given real IP.
        If no random IP exists, a new one is created and a message is logged indicating it.
        """
        if ip not in self.ips:
            random_ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
            self.logger.info("Registering new random IP: %s" % random_ip)
            self.ips[ip] = random_ip

    def process(self, msg, args, kwargs):
        """
        Modify the log message to replace any instance of an IP in msg or args with its assigned random IP.
        """
        new_args = []
        for arg in args:
            if type(arg) == str:
                for ip in self.regex.findall(arg):
                    new_ip = self.get_ip(ip)

                    arg = arg.replace(ip, self.ips[ip])
            
            new_args.append(arg)

        for ip in self.regex.findall(msg):
            if ip not in self.ips:
                random_ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
                self.logger.debug("Registering new random IP: %s" % random_ip)
                self.ips[ip] = random_ip
            new_ip = self.get_ip(ip)

            msg = msg.replace(ip, self.ips[ip])
        
        return msg, tuple(new_args), kwargs

def close_logger(logger):
    """
    Closes open file handles for a given logger.
    """
    # Close the file handles so we don't hold a ton of file descriptors open
    handlers = logger.handlers[:]
    for handler in handlers:
        if isinstance(handler, logging.FileHandler):
            handler.close()


class Logger():
    """
    Logging class context manager, as a thin wrapper around the logging class to help
    handle closing open file descriptors.
    """
    def __init__(self, log_dir, logger_name, log_name, environment_id, log_level="DEBUG"):
        self.log_dir = log_dir
        self.logger_name = logger_name
        self.log_name = log_name
        self.environment_id = environment_id
        self.log_level = log_level
        self.logger = None

    def __enter__(self):
        """
        Sets up a logger.
        """
        self.logger = get_logger(PROJECT_ROOT, self.log_dir, self.logger_name, self.log_name, self.environment_id, log_level=self.log_level)
        return self.logger

    def __exit__(self, exc_type, exc_value, tb):
        """
        Closes file handles.
        """
        close_logger(self.logger)



def get_console_log_level():
    """
    returns log level of console handler
    """
    return CONSOLE_LOG_LEVEL


def get_plugins():
    """
    Iterates over this current directory to retrieve plugins.
    """
    plugins = []
    for f in os.listdir(os.path.join(PROJECT_ROOT, "plugins")):
        if os.path.isdir(os.path.join(PROJECT_ROOT, "plugins", f)) and "__pycache__" not in f:
            plugins.append(f)
    return plugins


def import_plugin(plugin, side):
    """
    Imports given plugin.
    Args:
        - plugin: plugin to import (e.g. "http")
        - side: which side of the connection should be imported ("client" or "server")
    """

    # Define the full module for this plugin
    mod = "plugins.%s.%s" % (plugin, side)

    path = os.path.join(PROJECT_ROOT, "plugins", plugin)
    if path not in sys.path:
        sys.path.append(path)

    # Import the module
    importlib.import_module(mod)

    # Predicate to filter classmembers
    def check_plugin(obj):
        """
        Filters class members to ensure we get only enabled Plugin subclasses
        """
        return inspect.isclass(obj) and \
                issubclass(obj, plugins.plugin.Plugin) and \
                (obj != plugins.plugin_client.ClientPlugin and \
                 obj != plugins.plugin_server.ServerPlugin and \
                 obj != plugins.plugin.Plugin) and \
                obj(None).enabled

    # Filter the class members of the imported module to find our Plugin subclass
    clsmembers = inspect.getmembers(sys.modules[mod], predicate=check_plugin)

    # Sanity check the class members we identified
    assert clsmembers, "Could not find plugin %s" % mod
    assert len(clsmembers) == 1, "Too many matching plugins found for %s" % mod

    # Extract the class - clsmembers[0] is a tuple of (name, class)
    _, cls = clsmembers[0]

    # Return the module path and class
    return mod, cls


def build_command(args):
    """
    Given a dictionary of arguments, build it back into a command line string.
    """
    cmd = []
    for opt in args:
        # Don't pass along store true args that are false
        if args[opt] in [False, None]:
            continue
        cmd.append("--%s" % opt.replace("_", "-"))
        # If store true arg, we don't need to pass the value
        if args[opt] is True:
            continue

        if args[opt] is '':
            cmd.append("''")
        elif " " in str(args[opt]):
            cmd.append("\"" + str(args[opt]) + "\"")
        else:
            cmd.append(str(args[opt]))
    return cmd


def string_to_protocol(protocol):
    """
    Converts string representations of scapy protocol objects to
    their actual objects. For example, "TCP" to the scapy TCP object.
    """
    if protocol.upper() == "TCP":
        return TCP
    elif protocol.upper() == "IP":
        return IP
    elif protocol.upper() == "UDP":
        return UDP


def get_id():
    """
    Returns a random ID
    """
    return ''.join([random.choice(string.ascii_lowercase + string.digits) for k in range(8)])


def setup_dirs(output_dir):
    """
    Sets up Geneva folder structure.
    """
    ga_log_dir = os.path.join(output_dir, "logs")
    ga_flags_dir = os.path.join(output_dir, "flags")
    ga_packets_dir = os.path.join(output_dir, "packets")
    ga_generations_dir = os.path.join(output_dir, "generations")
    ga_data_dir = os.path.join(output_dir, "data")
    for directory in [ga_log_dir, ga_flags_dir, ga_packets_dir, ga_generations_dir, ga_data_dir]:
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
    return ga_log_dir


def get_from_fuzzed_or_real_packet(environment_id, real_packet_probability, enable_options=True, enable_load=True):
    """
    Retrieves a protocol, field, and value from a fuzzed or real packet, depending on
    the given probability and if given packets is not None.
    """
    packets = actions.utils.read_packets(environment_id)
    if packets and random.random() < real_packet_probability:
        packet = random.choice(packets)
        return packet.get_random()
    return layers.packet.Packet().gen_random()


def read_packets(environment_id):
    """
    Reads the pcap file associated with the last evaluation of this strategy.
    Returns a list of Geneva Packet objects.
    """
    if not environment_id:
        return None

    packets_path = os.path.join(RUN_DIRECTORY, "packets", "original_" + str(environment_id) + ".pcap")
    if not os.path.exists(packets_path):
        return None

    parsed = []
    try:
        packets = rdpcap(packets_path)
        parsed = [layers.packet.Packet(p) for p in packets]
    except Exception as e:
        print(e)
        print("FAILED TO PARSE!")

    return parsed


def punish_fitness(fitness, logger, eng):
    """
    Adjusts fitness based on additional optimizer functions.
    """
    if not eng:
        logger.warning("Requested fitness adjustment without an engine - returning original fitness.")
        return fitness
    logger.debug("Initiating fitness adjustment")
    if eng and eng.strategy:
        fitness = punish_complexity(fitness, logger, eng.strategy)
        fitness = punish_unused(fitness, logger, eng.strategy)
    if fitness > 0:
        overhead = int(eng.overhead / 2)
        logger.debug("Punishing for overhead: %d" % overhead)
        fitness -= overhead

    return fitness


def punish_unused(fitness, logger, ind):
    """
    Punishes strategy for each action that was not run.
    """
    if not ind:
        return fitness
    logger.debug("Punishing for unused actions")
    num_unused = [action_tree.ran for action_tree in ind.out_actions].count(False)
    fitness -= (num_unused * 10)
    logger.debug(" - Number of unused actions in out forest: %d" % num_unused)
    num_unused = [action_tree.ran for action_tree in ind.in_actions].count(False)
    fitness -= (num_unused * 10)
    logger.debug(" - Number of unused actions in in forest: %d" % num_unused)
    return fitness


def punish_complexity(fitness, logger, ind):
    """
    Reduces fitness based on number of actions - optimizes for simplicity.
    """
    if not ind:
        return fitness
    # Punish for number of actions
    if fitness > 0:
        logger.debug("Punishing for complexity: %d" % len(ind))
        fitness -= len(ind)
    return fitness


def write_fitness(fitness, output_path, eid):
    """
    Writes fitness to disk.
    """
    try:
        float(fitness)
    except ValueError:
        print("Given fitness (%r) is not a number!" % fitness)
        raise
    fitpath = os.path.join(PROJECT_ROOT, output_path, FLAGFOLDER, eid) + ".fitness"
    with open(fitpath, "w") as fitfile:
        fitfile.write(str(fitness))


def get_interface():
    """
    Chooses an interface on the machine to use for socket testing.
    """
    ifaces = netifaces.interfaces()
    for iface in ifaces:
        if "lo" in iface:
            continue
        info = netifaces.ifaddresses(iface)
        # Filter for IPv4 addresses
        if netifaces.AF_INET in info:
            return iface


def get_worker(name, logger):
    """
    Returns information dictionary about a worker given its name.
    """
    path = os.path.join("workers", name, "worker.json")
    if os.path.exists(name):
        path = name

    dirpath = os.path.dirname(path)

    if not os.path.exists(path):
        return None

    with open(path, "r") as fd:
        data = json.load(fd)

    # If there is a private key, update the path to be relative to the project base
    if data.get("keyfile"):
        data["keyfile"] = os.path.join(dirpath, data["keyfile"])

    return data

def write_detectability(detecatability, count,preds):
    
    with open(os.path.join(RUN_DIRECTORY,'detectability.csv'), 'a') as f:
            write = csv.writer(f)
            write.writerow([datetime.datetime.now().strftime("%H:%M:%S")]+detecatability)
            #write.writerow('\n')
    
    with open(os.path.join(RUN_DIRECTORY,'detection_count.csv'), 'a') as f:
            write = csv.writer(f)
            write.writerow([datetime.datetime.now().strftime("%H:%M:%S"),count])
            #write.writerow("\n")
            
    with open(os.path.join(RUN_DIRECTORY,'preds.csv'), 'a') as f:
            write = csv.writer(f)
            write.writerow([datetime.datetime.now().strftime("%H:%M:%S"),preds])
            
def check_flow_exist(flow,flows):
    ''' check whether a flow is already detected in pcap file'''
    
    for flow_i in flows.keys():
        if flow[0] == flow_i[0] and flow[1] == flow_i[1]:
            return 1,flow_i
        if flow[0] == flow_i[1] and flow[1] == flow_i[0]:
            return 1,flow_i
    return 0,0


#@profile
def parse_pcap(environment_id, args, client_ip, index=None):
    
    '''read and parse one pcap file'''
    
    # Defining imports here to avoid error    
    import numpy as np
    import pandas as pd
    
    if index != None:
        filename = os.path.join(RUN_DIRECTORY, "packets", str(environment_id)+"_client" +str(index)+ ".pcap")
    else:
        filename = os.path.join(RUN_DIRECTORY, "packets", str(environment_id)+"_client" + ".pcap")
    print("Reading ",filename)
    if not os.path.exists(filename):
        return None
    file_stats = os.stat(filename)
    if file_stats.st_size == 0:
        print("No traffic is found. Connection could be broken!")
        return None
    
    flow=[]
    client_flags_count = {}
    ips = []
    
    
    for i,packet in enumerate(PcapReader(filename)):
        if TCP not in packet:
            continue
       
        try:
            if str(bytes(packet[TCP].payload).decode("utf-8") ) == 'checking' and packet[TCP].flags =='S':
                #print('ignoring the checking packet')
                continue
        except UnicodeDecodeError:
            pass
        # Extracting all flows
        #flow = []#(packet[TCP].sport, packet[TCP].dport)
        #if check_flow_exist(flow,flows)[0] == 0:
        if flow == []:
            print('\n --Adding new flow', flow)
            flow.append(packet)
        else:
        #    flow = check_flow_exist(flow,flows)[1]
            
            dup=0
            for packet_i in flow:
                if (packet[TCP].flags == packet_i[TCP].flags and 
                       packet[TCP].seq == packet_i[TCP].seq and
                       packet[TCP].payload == packet_i[TCP].payload):
                    #print('Duplicate packet is ignored')
                    dup=1
                    continue
            if dup == 0:
                flow.append(packet)
        #print(flow)
    
    def parse_flow(flow):
        
        i=0
        flow_size=0
        max_packet_size_per_flow = 0
        fragmented_packets = []
        #TCP_seq = []
        IPoverlapping = 0
        TCPoverlapping = 0
        TCP_seq_range = []
        corrupt_chksm = 0
        corrupt_dataofs = 0
        low_ttl = 0
        all_ttl = {}
        Non_zero_SYN=0
        flow_flags = {}
        for packet in flow:#flows[flow]:
            #try:
            
            if packet[IP].src != client_ip and str(packet[TCP].flags).find('R') == -1 :
                continue
            #print("/**Packet {}**/".format(i+1))
            #print("--Summary : {}".format(packet.summary()))
            #if packet[TCP].dport == 80:
            '''packet max size'''
            max_packet_size_per_flow = max(len(packet[TCP].payload),max_packet_size_per_flow) 

            '''flow size'''
            flow_size += len(packet[TCP].payload)

            '''extract fragmented packets'''
            if packet[IP].flags==1 or packet[IP].frag > 0:
                fragmented_packets.append(packet)

            '''Extracting Payloads'''
            payload = bytes(packet[TCP].payload)
            #print("--payload {}\n".format(payload))

            '''Extracting Flags'''
            flags = str(packet[TCP].flags)
            if packet[IP].src == client_ip:
                '''Check if it is a non-zero SYN'''
                if flags == 'S' and len(payload) != 0:
                    Non_zero_SYN+=1
                # add to current pcap flags
                if flags in flow_flags.keys():
                    flow_flags[flags]+=1
                else:
                    flow_flags[flags]=1

                # add to all pcap flags
                if flags in client_flags_count.keys():
                    client_flags_count[flags]+=1
                else:
                    client_flags_count[flags]=1
            #elif packet[IP].src == censor_ip:
            #    if flags in censor_flags_count.keys():
            #        censor_flags_count[flags]+=1
            #    else:
            #        censor_flags_count[flags]=1

            '''Extracting IPs'''
            ips.append(packet[IP].dst)

            '''Extracting Checksum and dataofs'''
            chksum = packet[TCP].chksum
            dataofs = packet[TCP].dataofs
            #print("--TCP checksum {}".format(chksum))
            #print('--TCP dataofs: ',dataofs)
            del packet[TCP].chksum
            del packet[TCP].dataofs
            try:
                out_all = packet.show2(dump=True)
            

                ## extract checksum
                out = out_all[out_all.find('###[ TCP ]###'):]
                out = out[out.find('chksum    = ')+len('chksum    = '):]
                out = out[:out.find(' ')]
                try:
                    correct_chksum = int(out, 16)
                    #print("--Recomputed TCP checksum {}".format(correct_chksum))
                    if correct_chksum != chksum:
                        corrupt_chksm+=1
                except ValueError:
                    #print('{} found as correct_chksum')
                    pass
                ## extract dataofs
                out = out_all[out_all.find('###[ TCP ]###'):]
                out = out[out.find('dataofs   = ')+len('dataofs   = '):]
                out = out[:out.find(' ')]
                try:
                    correct_dataofs = int(out)
                    #print("--Recomputed TCP dataofs {}".format(correct_dataofs))
                    if correct_dataofs != dataofs:
                        corrupt_dataofs+=1
                except ValueError:
                    #print('{} found as correct_dataofs')
                    pass
            except:
                pass

            '''Extracting ttl'''
            #print(packet[IP].ttl)
            if packet[IP].ttl <= 10:
                low_ttl+=1
            if packet[IP].src in all_ttl.keys():
                all_ttl[packet[IP].src].append(packet[IP].ttl)
            else:
                all_ttl[packet[IP].src] = [packet[IP].ttl]
            

            '''geneva TCP seq range'''
            #print("--packet's TCP sequence range is [{},{}]".format(packet[TCP].seq,packet[TCP].seq+len(bytes(packet[TCP].payload))))
            if len(bytes(packet[TCP].payload)) != 0 and packet[IP].src == client_ip:
                TCP_seq_range.append([packet[TCP].seq, packet[TCP].seq+len(bytes(packet[TCP].payload))])

            #except Exception as e:
            #    pass
            i+=1
        ## TTL Variance
        ttl_var=0
        #print(all_ttl)
        for ip in all_ttl.keys():
            if ip == client_ip:
                ttl_var+=np.var(all_ttl[ip])
        #if len(all_ttl.keys()) != 0:
        #    ttl_var = ttl_var/len(all_ttl.keys())
        

        ## Overlapping TCP segements
        overlapped = [] # a list of overlapped seq ranges indices

        for i in range(len(TCP_seq_range)):
            seq_r = TCP_seq_range[i]
            if seq_r[1] == seq_r[0]:
                continue

            for j in range(len(TCP_seq_range)):
                check_r = TCP_seq_range[j]
                if i==j:   
                    continue
                if check_r[1] == check_r[0]:
                    continue
                #if seq_r[0] == check_r[0] and seq_r[1] == check_r[1]:
                #    j+=1
                #    continue
                if check_r[0] >= seq_r[0] and check_r[0] < seq_r[1]:
                    ov=[]
                    ov.append(i)
                    ov.append(j)
                    ov.sort()
                    if ov not in overlapped:
                        #print(ov)
                        overlapped.append(ov)
                        continue
                elif check_r[0] <= seq_r[0] and seq_r[0] < check_r[1]:
                    ov=[]
                    ov.append(i)
                    ov.append(j)
                    ov.sort()
                    if ov not in overlapped:
                        #print(ov)
                        overlapped.append(ov)
                        continue
        TCPoverlapping = len(overlapped)

        ## Overlapping IP Fragments
        if len(fragmented_packets) != 0:
            ## collecting unique IP IDs
            uniqipids={}
            for a in fragmented_packets:
                uniqipids[a[IP].id]='we are here'

            for ipid in uniqipids.keys():
                #print("Packet fragments found. Collecting fragments now.")
                fragmenttrain = [a for a in fragmented_packets if a[IP].id == ipid]
                allocated_bytes = []
                for a in fragmenttrain:
                    frag_offset = a[IP].frag*8
                    for byte in range(frag_offset, frag_offset+len(a[IP].payload)+1):
                        if byte not in allocated_bytes:
                            allocated_bytes.append(byte)
                        else:
                            #print("Overlapping packets are found!")
                            IPoverlapping+=1
        else:
            print('No fragment is found!')    
        
        
        return Non_zero_SYN, flow_flags, flow_size, max_packet_size_per_flow, IPoverlapping, TCPoverlapping, corrupt_chksm, corrupt_dataofs, low_ttl, ttl_var
    
    
    
    
    Non_zero_SYN,flow_flags, flow_size, max_packet_size_per_flow, IPoverlapping, TCPoverlapping, corrupt_chksm, corrupt_dataofs, low_ttl, ttl_var = parse_flow(flow) 
    
        
        
    print('SYN with non-zero payload',Non_zero_SYN)    
    print('flow_size',flow_size)
    print('max_packet_size_per_flow',max_packet_size_per_flow)
    print('IPoverlapping',IPoverlapping)
    print('TCPoverlapping',TCPoverlapping)
    print('corrupt_chksm',corrupt_chksm)
    print('corrupt_dataofs',corrupt_dataofs)
    print('low_ttl',low_ttl)
    print('flow_flags',flow_flags)
    print('ttl_var',ttl_var)
        
            
    #Non_zero_SYN, flags, flow_size, max_pckt_size_per_flow, IPoverlapping, TCPoverlapping, corrupt_chksm, corrupt_dataofs, low_ttl, ttl_var = parse_pcap(filename)
    
    data = {}
    #for flow_i in  range(len(allpcap_flow_size)):
    record={}
    record['# Non_zero_SYN'] = Non_zero_SYN
    record['flags'] = flow_flags
    record['size']=flow_size
    record['Max_pckt_size'] = max_packet_size_per_flow
    #record['# overlapping IP fragments']=IPoverlapping[flow_i]
    record['# overlapping TCP segments']= TCPoverlapping
    #record['# of corrupt checksum']=corrupt_chksm
    record['# of corrupt dataofs']=corrupt_dataofs
    #record['# low ttl'] = low_ttl
    record['ttl variance'] = ttl_var

    data[str(environment_id)] = record
    if record['flags'] in [{},{'S': 1}]:
        return None
    if data != {}:
        df = pd.DataFrame.from_dict(data, orient='index')
    else:
        return None
    
    # store envirnment data to csv
    csv_path = os.path.join(RUN_DIRECTORY, "csv")
    if not os.path.exists(csv_path):
        os.mkdir(csv_path)
    
    
    if index != None:
        df.to_csv(os.path.join(csv_path,str(environment_id)+"_client" +str(index)+'.csv'), sep=',')
    else:
        df.to_csv(os.path.join(csv_path,str(environment_id)+'.csv'), sep=',')
    
    return df