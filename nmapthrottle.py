#!/usr/bin/env python2
#
# Author: Andy Marks
# Date: 07/19/15
#
# Modified by: Gilles Biagomba
# Date: 10/12/18
#
# Function:  Reformat nmap output as one row per combination of
# IP address / Protocol Type (TDP/UDP) / Port Status / Port Number.
# Importing this format into a spreadsheet, pivot tables can 
# be used to quickly create a wide variety of report formats.
#
import os.path
import argparse
import subprocess
import sys
import os
import time
import errno
import array
import re

def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return open(arg, 'r')  # return an open file handle
#
def process_exists(tst):
    """Check whether pid exists in the current process table."""
    retcode = tst.poll()
    if retcode is None:
       return True
    else:
       return False

#
###############################################################
#
# Begin ---->>> get_running_processes <<<-----
#
def get_running_processes():
#
    running_processes = 0
    for s in process_array:
        if process_exists(s):
           running_processes = running_processes + 1
    return running_processes
#
# End End End ---->>> get_running_processes <<<-----
#
###############################################################
#
# Begin ---->>> Main program <<<-----
#
# The debug flag essentially displays trace messages to aid in
# troubleshooting.  It must be 'yes' to show the messages.
#
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--inputfile", dest="filename", # required=True,
                    help="Input file with IP addresses, one per line. Default name is targets.txt",
                    metavar="FILE",
                    type=lambda x: is_valid_file(parser, x), default='targets.txt')
parser.add_argument("-s", "--sleep", help="Amount of time in seconds to sleep between status checks",
                    nargs='?', const=10, type=int, default=10)
parser.add_argument("-c", "--concurrent", help="Maximum number of concurrent processes allowed",
                    nargs='?', const=3, type=int, default=3)
parser.add_argument("-d", "--debug", help="Show debug messages",action="store_true")
args = parser.parse_args()

max_concurrent_scans = args.concurrent
sleep_seconds = args.sleep
file = args.filename
if args.debug:
   debugf = 'yes'
else:
   debugf = 'no'
if debugf == 'yes':
   print 'File: '+str(args.filename)
   print 'Print debug messages: '+debugf
   print 'Sleep '+str(sleep_seconds)+' seconds between status checks.'
   print 'Maximum concurrent scans: '+str(max_concurrent_scans)

# All processes are stored in process_array just after they are started.
# This allows for checking if it is still running. We count the number
# of processes in the following variable.                                      
#
if file == "targets.txt":
    file = open('targets.txt', 'r')

ip_array = []
for line in file:
   ip_array.append([str(line).rstrip()])

if debugf == 'yes':
   print ip_array

#####################################################################
#
# Beginning of process execution and throttling loop.
#
process_array = []
running_scans = 0
if max_concurrent_scans > len(ip_array):
   max_concurrent_scans = len(ip_array)

while running_scans > 0 or len(ip_array) > 0:
   if running_scans < max_concurrent_scans:
      number_to_kickoff = max_concurrent_scans - running_scans
      if debugf == 'yes':
         print number_to_kickoff
      if len(ip_array) > 0:
         for startloop in range(0,number_to_kickoff):
            if debugf == 'yes':
               print ip_array[0]
            ip_address = str(ip_array[0])
            # filename='nmap-'+(ip_address)[0]
            # p = subprocess.Popen(["nmap", "-A", "-R", "--reason", "--resolve-all", "-sS", "-sU", "-sV", "--script=ssl-enum-ciphers", "-p 0,22,25,80,143,280,443,445,465,563,567,585,587,591,593,636,695,808,832,898,981,989,990,992,993,994,995,1090,1098,1099,1159,1311,1360,1392,1433,1434,1521,1527,1583,2083,2087,2096,2376,2484,2638,3071,3131,3132,3269,3306,3351,3389,3424,3872,3873,4443,4444,4445,4446,4843,4848,4903,5223,5432,5500,5556,5671,5672,5800,5900,5989,6080,6432,6619,6679,6697,6701,6703,7000,7002,7004,7080,7091,7092,7101,7102,7103,7105,7107,7109,7201,7202,7301,7306,7307,7403,7444,7501,7777,7799,7802,8000,8009,8080,8081,8082,8083,8089,8090,8140,8191,8243,8333,8443,8444,8531,8834,8888,8889,8899,9001,9002,9091,9095,9096,9097,9098,9099,9100,9443,9999,10000,10109,10443,10571,10911,11214,11215,12043,12443,12975,13722,17169,18091,18092,18366,19812,20911,23051,23642,27724,31100,32100,32976,33300,33840,36210,37549,38131,38760,41443,41581,41971,43778,46160,46393,49203,49223,49693,49926,55130,55443,56182,57572,58630,60306,62657,63002,64779,65298", "-oA", filename, (ip_address)[0]],
            # stdout=subprocess.PIPE)
            # process_array.append(p);
            # del ip_array[0]
            print("About to scan " + (ip_address)[0] + " before if/else statements") # degubbing
            if re.search(r"[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\/[0-9]\{1,\}",ip_address) is True:
                ip_address = list(ip_address.split())
                print ip_address # debugging
                print("About to scan " + (ip_address)[0] + " first conditional") # degubbing
                filename='nmap-{0}'.format(ip_address.split('/')[0])
                p = subprocess.Popen(["nmap", "-A", "-R", "--reason", "--resolve-all", "-sS", "-sU", "-sV", "--script=ssl-enum-ciphers", "-p 0,22,25,80,143,280,443,445,465,563,567,585,587,591,593,636,695,808,832,898,981,989,990,992,993,994,995,1090,1098,1099,1159,1311,1360,1392,1433,1434,1521,1527,1583,2083,2087,2096,2376,2484,2638,3071,3131,3132,3269,3306,3351,3389,3424,3872,3873,4443,4444,4445,4446,4843,4848,4903,5223,5432,5500,5556,5671,5672,5800,5900,5989,6080,6432,6619,6679,6697,6701,6703,7000,7002,7004,7080,7091,7092,7101,7102,7103,7105,7107,7109,7201,7202,7301,7306,7307,7403,7444,7501,7777,7799,7802,8000,8009,8080,8081,8082,8083,8089,8090,8140,8191,8243,8333,8443,8444,8531,8834,8888,8889,8899,9001,9002,9091,9095,9096,9097,9098,9099,9100,9443,9999,10000,10109,10443,10571,10911,11214,11215,12043,12443,12975,13722,17169,18091,18092,18366,19812,20911,23051,23642,27724,31100,32100,32976,33300,33840,36210,37549,38131,38760,41443,41581,41971,43778,46160,46393,49203,49223,49693,49926,55130,55443,56182,57572,58630,60306,62657,63002,64779,65298", "-oA", filename, (ip_address)[0]],
                stdout=subprocess.PIPE)
                process_array.append(p);
                del ip_array[0]
            else:
                ip_address = list(ip_address.split())
                print ip_address # debugging
                print("About to scan " + (ip_address)[0] + " second conditional") # degubbing
                filename='nmap-'+(ip_address)[0]
                p = subprocess.Popen(["nmap", "-A", "-R", "--reason", "--resolve-all", "-sS", "-sU", "-sV", "--script=ssl-enum-ciphers", "-p 0,22,25,80,143,280,443,445,465,563,567,585,587,591,593,636,695,808,832,898,981,989,990,992,993,994,995,1090,1098,1099,1159,1311,1360,1392,1433,1434,1521,1527,1583,2083,2087,2096,2376,2484,2638,3071,3131,3132,3269,3306,3351,3389,3424,3872,3873,4443,4444,4445,4446,4843,4848,4903,5223,5432,5500,5556,5671,5672,5800,5900,5989,6080,6432,6619,6679,6697,6701,6703,7000,7002,7004,7080,7091,7092,7101,7102,7103,7105,7107,7109,7201,7202,7301,7306,7307,7403,7444,7501,7777,7799,7802,8000,8009,8080,8081,8082,8083,8089,8090,8140,8191,8243,8333,8443,8444,8531,8834,8888,8889,8899,9001,9002,9091,9095,9096,9097,9098,9099,9100,9443,9999,10000,10109,10443,10571,10911,11214,11215,12043,12443,12975,13722,17169,18091,18092,18366,19812,20911,23051,23642,27724,31100,32100,32976,33300,33840,36210,37549,38131,38760,41443,41581,41971,43778,46160,46393,49203,49223,49693,49926,55130,55443,56182,57572,58630,60306,62657,63002,64779,65298", "-oA", filename, (ip_address)[0]],
                stdout=subprocess.PIPE)
                process_array.append(p);
                del ip_array[0]

   running_scans = get_running_processes()
   print 'Running scans: '+str(running_scans)
  # Sleep for awhile so as not to waste too much system resources rechecking.
   time.sleep(sleep_seconds)
#
# End of process execution and throttling loop.
#
#####################################################################
#
# Beginning the nmap output file consolidation.
#

filenames = os.listdir('.')
content = ''
for f in filenames:
    if f.startswith("nmap") and f.endswith(".txt"):
       content = content + '\n' + open(f).read()
       open('joined_file.txt','wb').write(content)
line_work = [line.strip() for line in open('joined_file.txt')]                 
lines=[]
for r in line_work:
    if re.match("(.*)Port(.*)", r):
       lines.append(r)
       if debugf == 'yes':
          print r

#
# End the nmap output file consolidation.
#
##############################################################
#
# Beginning of main print loop.
#
#   Open the report output file:
#
myfile = open('final.txt', 'w')
#
# One line at a time, we read the lines array and use string functions
# to build the record for final.txt .
#
for s in lines:                                                                
   line = s
   if debugf == 'yes':
      print s

# Working lists for parsing port information.
   port_fields = []
   tcp_ports = []
   openfiltered_udp_ports = []
   open_udp_ports = []

#
# The IP address is parse and stored for later inclusion in the output
# file at the beginning of the line.  The key part of the search method
# is \(\).  The search string is actually looking for (), but the back-
# slash is necessary as an escape character.  Essentially, we are looking
# for (), which occurs on every line in the line array.  The rest of the 
# line, before and after (\(\)) means there can be a string of characters
# before or after the one for which we are searching.
#
   end_of_ip_address = re.search(r"[^a-zA-Z](\(\))[^a-zA-Z]", line).start()
   ip_addr = line[6:end_of_ip_address]
#
# The following code group strips off extraneous information from the
# left and right of the line, leaving only port information.
#
   port_pos = re.search(r"[^a-zA-Z](Ports: )[^a-zA-Z]", line).start()
   line_stripped_left = line[port_pos+8:]

   if re.search(r"[^a-zA-Z](Ignored)[^a-zA-Z]",line_stripped_left) is not None:
      right_end_pos = re.search(r"[^a-zA-Z](Ignored)[^a-zA-Z]", line_stripped_left).start()
      line_stripped_lr = line_stripped_left[:right_end_pos-1]                  
   else:
      line_stripped_lr = line_stripped_left
#
# The line has been stripped of extraneous information and only port information remains.
# Those fields are separated by a space, and can be easily stored in an array.
#

   ports = line_stripped_lr.split(" ")
   if debugf == 'yes':
      print ports

#
# The port array populated above is now evaluated, one port at a time, and the UDP and
# TCP port arrays are populated along the way.
#

   for s in ports:
       port_fields_work = s                                                    
       port_fields = port_fields_work.split("/")
       if debugf == 'yes':
          print port_fields
       if port_fields[2]=="tcp":
          tcp_ports.append(port_fields[0])
       if port_fields[2]=="udp" :
          if port_fields[1]=='open|filtered':
             openfiltered_udp_ports.append(port_fields[0])
          else:
             open_udp_ports.append(port_fields[0])
           
   for t in tcp_ports:
      output_line = ip_addr+","+"OPEN"+",TCP,"+str(t.strip())
      myfile.write("%s\n" % output_line)

   for u in open_udp_ports:
      output_line = ip_addr+","+"OPEN"+",UDP,"+str(u.strip())
      myfile.write("%s\n" % output_line)

   for u in openfiltered_udp_ports:
      output_line = ip_addr+","+"OPEN|FILTERED"+",UDP,"+str(u.strip())
      myfile.write("%s\n" % output_line)
#
# End of main print loop.
#
##############################################################
