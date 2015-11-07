__author__ = 'nacho'

import sys
import cmd
import Capture
from cap_model import *

from os import listdir

class Preter(cmd.Cmd):
    """Interpreter"""

    def __init__(self):
        cmd.Cmd.__init__(self)
        cmd.Cmd.prompt='>>> '
        self.cap=Capture.Capture()

    def do_quit(self,line):
        return True


    def do_open(self,fich):

        cod=self.cap.open(fich)
        if cod==1:
            print "Capture successfully loaded."
        else:
            print "Error opening capture."

    def help_open(self):
        print 'opens a pcap file'
        print 'Usage: open <file>'

    def do_ls(self,dire):
        l=listdir('.')
        print l

    def help_ls(self):
        print 'lists files in current directory'

    def do_analyze(self,cap):
        try:
            self.cap.pcap
        except Exception, e:
            return 0
        else:
            for ts,buf in self.cap.pcap:
                r=self.cap.analyze_packet(buf)
                a=str(self.cap.processed_packets)+"/"+str(self.cap.npackets)
                print "{}\r".format(a),
        # OjO aqui
        self.cap.dbsession.commit()
        print "Capture analyzed!"

    def do_show_orphans(self,line):
        (orphan,odds)=self.cap.orphans()
        cont=0
        for i in orphan:
            print str(cont)+") "+i[1]+":"+str(i[2])+" -> "+i[4]+":"+str(i[5])+" "+str(i[6])
            cont+=1

    def do_analyze_orphans(self,line):
        self.cap.analyze_orphans()
        self.cap.dbsession.commit()

    def do_orphan_ports(self,line):
        self.cap.count_orphan_ports()
        print "TCP"
        print "==="
        cont=0
        for k in self.cap.orphan_tcps:
            print str(cont)+") "+str(k)+" : "+str(self.cap.orphan_tcps[k])
            cont+=1
        print "UDP"
        print "==="
        for k in self.cap.orphan_udps:
            print str(cont)+") "+str(k)+" : "+str(self.cap.orphan_udps[k])
            cont+=1

    def help_analyze(self):
        print 'analyzes the current capture'


    def do_list_ips(self,line):
        l=self.cap.ips()
        for i in l:
            print i

    def help_list_ips(self):
        print 'lists IP addresses present in the current capture'

    def do_list_captures(self,line):
        caps=self.cap.captures()
        for id,f,des in caps:
            print str(id)+"\t("+f+"):\t"+str(des)

    def do_load_db(self,line):
        l=line.split()
        if len(l)==0:
            print "*** need to provide a capture identifier (try list_captures)"
            return
        try:
            cap_id=int(l[0])
        except ValueError:
            print "*** capture identifier should be an integer"
            return
        self.cap.load(cap_id)
