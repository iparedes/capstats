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
        engine = create_engine('sqlite:///orm_in_detail.sqlite')
        Session = sessionmaker()
        Session.configure(bind=engine)
        self.dbsession=Session()
        Base.metadata.create_all(engine)


    def do_quit(self,line):
        return True


    def do_open(self,fich):

        self.cap=Capture.Capture(self.dbsession)
        cod=self.cap.open(fich)
        if cod==1:
            print "Capture successfully loaded."
        else:
            print "Error opening capture."

    def do_ls(self,dire):
        l=listdir('.')
        print l

    def do_analyze(self,cap):
        try:
            self.cap.pcap
        except Exception, e:
            return 0
        else:
            for ts,buf in self.cap.pcap:
                print self.cap.analyze_packet(buf)

    def do_list_ips(self,line):
        l=self.cap.ips()
        for i in l:
            print i
