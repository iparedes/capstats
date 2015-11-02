__author__ = 'nacho'

import dpkt
import socket

from cap_model import *

from sqlalchemy import exc,MetaData,Table



class Capture():
    def __init__(self):
        engine = create_engine('sqlite:///orm_in_detail.sqlite')
        Session = sessionmaker()
        Session.configure(bind=engine)
        self.dbsession=Session()
        self.orphanpackets=[]
        Base.metadata.create_all(engine)

    def open(self, fich):
        try:
            f = open(fich, "r")
            self.pcap = dpkt.pcap.Reader(f)
            self.npackets = len(list(self.pcap))


            self.dbcapture = capture(filename=fich)
            self.dbsession.add(self.dbcapture)
            self.dbsession.flush()
            self.dbsession.commit()

            return 1
        except IOError:
            return 0

    def analyze_packet(self, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        packet_size=len(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # IP packet
            ip = eth.data
            ipquad1 = socket.inet_ntoa(ip.src)
            ipquad2 = socket.inet_ntoa(ip.dst)
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                # TCP
                tcp = ip.data
                port1=tcp.sport
                port2=tcp.dport
                if ((tcp.flags & dpkt.tcp.TH_SYN) != 0) and ((tcp.flags & dpkt.tcp.TH_ACK) == 0):
                    # Start of 3-way handshake
                    self.add_ip(ipquad1)
                    self.add_ip(ipquad2)
                    self.add_conv(ipquad1,ipquad2,u"tcp",port2,packet_size)
                    #return ipquad1+","+ipquad2
                    return "SYN"
                else:
                    # Conversation started previous to the capture
                    possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                                  conversation.proto==u"tcp", \
                                                  conversation.ipsrc_ip==ipquad2, \
                                                  conversation.ipdst_ip==ipquad1, \
                                                  conversation.port==port1).all()
                    if len(possconv)==1:
                        # found matching conversation
                        possconv[0].packets+=1
                        possconv[0].bytes+=packet_size
                        self.dbsession.commit()
                        return ">"
                    else:
                        possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                                  conversation.proto==u"tcp", \
                                                  conversation.ipsrc_ip==ipquad1, \
                                                  conversation.ipdst_ip==ipquad2, \
                                                  conversation.port==port2).all()
                        if len(possconv)==1:
                            # found match in the other direction
                            possconv[0].packets+=1
                            possconv[0].bytes+=packet_size
                            self.dbsession.commit()
                            return "<"
                        else:
                            # Conversation not found
                            self.orphanpackets.append(eth)
                            return "Not added"


    def add_ip(self, ipa, mac=u""):
        """Adds an IP address to the current capture"""
        try:
            #exception while inserting IP means IP already inserted
            ip1 = ip(ip=ipa, mac=mac, capture_id=self.dbcapture.id)
            self.dbsession.add(ip1)

            self.dbsession.flush()
            self.dbsession.commit()
            return 1
        except exc.SQLAlchemyError:
            return 0

    def add_conv(self,ips,ipd,proto,port,packet_size):
        """Adds a conversation to the current capture"""
        try:
            conv1=conversation(ipsrc_ip=ips,ipdst_ip=ipd,proto=proto,port=port, \
                               capture_id=self.dbcapture.id,packets=1,bytes=packet_size)
            self.dbsession.add(conv1)
            self.dbsession.flush()
            self.dbsession.commit()
            return 1
        except exc.SQLAlchemyError:
            return 0


    def captures(self):
        caps=self.dbsession.query(capture).all()
        captures=map(lambda c: (c.id,c.filename,c.description), caps)
        return captures


    def ips(self):
        l=map(lambda w: w.ip, self.dbcapture.ips)
        return l

    def load(self,capid):
        self.dbcapture=self.dbsession.query(capture).filter(capture.id==capid).all()[0]
        pass