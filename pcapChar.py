#!/usr/bin/env python
#
# $Author: eric.zhong $
# $Id: pcapChar.py zhong@hp.com $
#

import re
import os
import time
import argparse
import sys
import datetime
import subprocess
import itertools

#import pyshark

# The following code includes a class that manages command line functionality
description =   "pcapChar.py: This script parses a pcap file and to summarize output of the network environment " \
                "The summary contains number of channels that was recorded, channel utilization (if present in pcap). " \
                "Number of APs and devices on each channel. " 
epilog =    "Author: Eric Zhong; Email: zhong@hp.com; " \
            "Last Updated: August 28, 2018"

class CmdLineIfc(object):
    def __init__(self):
        
        self.parser = argparse.ArgumentParser(description=description,epilog=epilog,prefix_chars="-/")
        self.parser.add_argument("-f","-F","/f","/F","--prnpcap",dest="prnpcap",required=True, help="System Path to pcap file captured")
        self.parser.add_argument("-k","-K","/k","/K","--keepfiles",dest="keep",action="store_true",help="no clean up of files")
        self.parser.add_argument("-v","-V","/v","/V","--verbose",dest="verbose",action="store_true",help="print out lines that are begin searched")
        self._args = self.parser.parse_args()
        new = ParsePcap( self._args.prnpcap, self._args.keep, self._args.verbose )
        
#tshark -r Session0021.pcap -2R wlan_radio.channel==1 -q -z endpoints,wlan
#get statistics from pcap
#which device to which AP
#all devices

    

class ChannelInfo(object):
    """Specific Channel info"""
    def __init__(self, filename, channel, verbose=False):
        self.fn = filename
        self.chan = channel        
        self.v = verbose
        self.newfn = ''.join(filename.split('.')[:-1])+'chan_'+str(channel)+'.pcap'
        self.APs =[]
        self.devicesTotal = []
        self.ave_utilization = 0
        self.min_utilization = 0
        self.max_utilization = 0
        self.devicesAssociated= {}
        
    def __str__(self):
        return 'Channel: {0} {1} {2:.3f}\t{3:.3f}\t{4}'.format(str(self.chan), str(self.newfn),self.min_utilization, self.max_utilization, len(self.APs)) 

    def remTmpFile(self):
        print 'removing', self.tmpfn
        os.remove(self.newfn)

    def parseChannel(self):
        if os.path.isfile(self.newfn):
            pass
        else:
            tsharkCall = ["tshark", "-r", self.fn , '-2R', 'wlan_radio.channel=='+str(self.chan), '-w', self.newfn ]
            if self.v:
                print tsharkCall
            tsharkProc = subprocess.Popen(tsharkCall,
                                        stdout=subprocess.PIPE, 
                                        executable="C:\\Program Files\\Wireshark\\tshark.exe")
            return tsharkProc
    
    def getAPs(self):
        fname = 'APsOnChan'+str(self.chan)
        tsharkOut  = open(fname, "a+")
        tsharkCall = ["tshark", "-r", self.newfn ,'-2R','wlan.fc.type_subtype == 0x0008', '-T', 'fields',  '-e', '_ws.col.Source', '-e', 'wlan.ssid', ]
        if self.v:
            print tsharkCall
        tsharkProc = subprocess.Popen(tsharkCall,
                                    stdout=tsharkOut, 
                                    executable="C:\\Program Files\\Wireshark\\tshark.exe")
        tsharkProc.wait()
        with open(fname) as f:
            allAPbeacons = []
            for line in f:
                try:
                    line.split()[1]
                except IndexError:
                    allAPbeacons.append((line.split()[0],''))
                else:
                    allAPbeacons.append((line.split()[0],line.split()[1]))
        self.APs = set(allAPbeacons)
        tsharkOut.close()
        #os.remove(fname)
        return self.APs

    def getAllDevices(self):
        pass
     
    def getNetAssociation(self):
        pass
     
    
    def getUtilization(self):
        fname = 'util_chan'+str(self.chan)
        tsharkOut  = open(fname, "a+")
        tsharkCall = ["tshark", "-r", self.newfn , '-T', 'fields', '-e', 'wlan.qbss.cu' ]
        if self.v:
            print tsharkCall
        tsharkProc = subprocess.Popen(tsharkCall,
                                    stdout=tsharkOut, 
                                    executable="C:\\Program Files\\Wireshark\\tshark.exe")
        tsharkProc.wait()
        with open(fname) as f:
            utils = []
            for line in f:
                if not line.isspace():
                    utils.append(line.strip())
            if utils:
                self.min_utilization = float(min(map(int,utils)))/255.0
                self.max_utilization = float(max(map(int,utils)))/255.0
                self.ave_utilization =  float(sum(map(int,utils)))/float((255*len(utils)))
        tsharkOut.close()
        os.remove(fname)
        return self.ave_utilization
        
    def getResponses(self):
        if os.path.isfile(self.tmpfn):
            pass
        else:
        #Ex.) tshark -r rd.pcap -T fields -e _ws.col.No. -e _ws.col.Time -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e _ws.col.Length -e snmp.value.octets > test.txt
            tsharkOut  = open(self.tmpfn, "a+")
            formating = [ '-T', 'fields', '-e', '_ws.col.No.',\
            '-e', '_ws.col.Time', '-e', '_ws.col.Source', '-e', '_ws.col.Destination', '-e', '_ws.col.Protocol',\
            '-e', '_ws.col.Length', '-e', '_ws.col.Info', '-e', 'snmp.value.octets']#snmp.var-bind_str
            xidFilter = ''
            for x in self.xids:
                xidFilter += "dns.id == "+x+ " || "
            tsharkCall = ["tshark", "-r", self.fn , "-2R", \
            xidFilter + "((frame.time_epoch>="+str(self.begin)+" && frame.time_epoch <= "+str(self.end)+") && snmp && ip.addr == "+str(self.ip)+")"]+formating
            if self.v:
                print tsharkCall
            tsharkProc = subprocess.Popen(tsharkCall,
                                        stdout=tsharkOut, 
                                        executable="C:\\Program Files\\Wireshark\\tshark.exe")
            return tsharkProc
        
        
class ParsePcap():
    def __init__(self, prnpcap, keep, verbose):
        self.verbose = verbose
        self.prnpcap = prnpcap
        self.channels = []
        self.SUBPROCESS_LIMIT = 10
        
        if self.prnpcap is not None:
            if '.txt' in self.prnpcap:
                self.pcap_summary(self.prnpcap)
            else:
                tsharkCall = ["tshark", "-r", self.prnpcap,"-Y", "wlan_radio.channel", "-T", "fields", "-e", "wlan_radio.channel"]
                data = self.runTshark(self.prnpcap, tsharkCall, 'tmp')
                self.getChannels(data)
                self.filterChannels()
                if self.verbose:
                    for i in self.channels:
                        print i
                self.subprocessQMngr()
                for i in self.channels:
                    APs = i.getAPs()
                    for a in APs:
                        print a
                    print i
                    break
                    
                
        #if not keep:
        #    self.cleanup()
    
    
    def getChannels(self,datalist):
        with open(datalist) as f:
            chans = f.read()
            chanlist = list(set(chans.split('\n')))
            chanlist = filter(None,chanlist)            
            Chan2Ghz = [int(i) for i in chanlist if (int(i) >= 1 and int(i)<= 14)]
            Chan5Ghz = [int(i) for i in chanlist if not (int(i) >=1  and int(i)<= 14)]
            Chan2Ghz.sort()
            Chan5Ghz.sort()
            self.Chan2Ghz = Chan2Ghz
            self.Chan5Ghz = Chan5Ghz
            if self.verbose:
                print '{}\n\n{}'.format(Chan2Ghz,Chan5Ghz)
    
    def filterChannels(self):
        for chan in self.Chan2Ghz:
            self.channels.append(ChannelInfo(self.prnpcap,chan))
        for chan in self.Chan5Ghz:
            self.channels.append(ChannelInfo(self.prnpcap,chan))
            
    def subprocessQMngr(self):
        counter = 0
        queue = []
        for i in self.channels: 
            if len(queue)<self.SUBPROCESS_LIMIT:
                queue.append(i.parseChannel())
            else:
                while len(queue)>=self.SUBPROCESS_LIMIT:
                    for run in xrange(len(queue)):
                        toremove = []
                        try:
                            if queue[run] == None:
                                toremove.append(run)
                            else:
                                try:
                                    if queue[run].poll() is not None:
                                        toremove.append(run)                                                
                                except Exception as e:
                                    pass
                            for rem in toremove:
                                queue.pop(rem)
                        except IndexError:
                            pass
                    if len(queue)<self.SUBPROCESS_LIMIT:
                        queue.append(i.parseChannel())
                    else:
                        time.sleep(1) 
            counter += 1
            print 'Percent complete:  ' + '{:.2%}\t{}/{}'.format((float(counter)/float(len(self.channels))),counter,len(self.channels)) + '\r', 
            sys.stdout.flush()
     

        
    def runTshark(self, file, tsharkCall, tmpname=""):
        #self.changeWiresharkSettings()
        self.textfile = file.split('.pcap')[0]+tmpname+'.txt'
        #tsharkCall = ["tshark", "-r", file, "-V","-T","pdml"]
        #bcastip = ('.').join(self.ip.split('.')[0:3])+'.255'
        #tsharkCall = ["tshark", "-r", file,"-t", "e", "-2R", "ip.addr == "+self.ip+" && (mdns || snmp) && \
        #    (ip.dst == 224.0.0.251 || ip.dst == 255.255.255.255 || ip.dst == "+bcastip+") && !frame contains googlecast && !dns.id eq 0000 && !dns.qry.class == 0x00ff"]
        if os.path.isfile(self.textfile):
            print 'Text File from PCAP file already exists!'
            pass
        else:
            if tmpname == "":
                tsharkOut = subprocess.PIPE
            else:
                tsharkOut  = open(self.textfile, "wb")
            tsharkProc = subprocess.Popen(tsharkCall,
                                stdout=tsharkOut, 
                                executable="C:\\Program Files\\Wireshark\\tshark.exe")
            print 'Starting to process pcap to text file:  ' + (time.strftime("%I:%M:%S"))
            print '<Hit Enter Key if Time stops moving>'
            while tsharkProc.poll() is None:
                print 'Processing pcap to text file:  ' + (time.strftime("%I:%M:%S")) + '\r',
                time.sleep(2)
            print 'Finished process pcap to text file:  ' + (time.strftime("%I:%M:%S"))
        if tmpname == "":
            return tsharkProc.stdout.read()
        else:
            return self.textfile

    def cleanup(self):
        for i in self.channels:
            i.remTmpFile()
    
if __name__ == "__main__":
    CmdLineIfc()


