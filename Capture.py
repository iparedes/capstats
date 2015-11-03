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
        self.__orphan_packets=[]
        self.__udp_packets=[]
        Base.metadata.create_all(engine)
        self.__well_known_udp=(53,67,68,69,79,88,113,119,123,135,137,138,139,161,162)

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
            ipquad1 = unicode(socket.inet_ntoa(ip.src))
            ipquad2 = unicode(socket.inet_ntoa(ip.dst))
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
                    return "TCP"
                else:
                    # Conversation started previous to the capture
                    (c,conv)=self.__match_conversation(ipquad1,port1,ipquad2,port2,u"tcp")
                    if (c=='?'):
                        # Conversation not found
                        self.__orphan_packets.append(eth)
                        return "Not added"
                    else:
                        conv.packets+=1
                        conv.bytes+=packet_size
                        self.dbsession.flush()
                        #self.dbsession.commit()
                        return c
            elif ip.p==dpkt.ip.IP_PROTO_UDP:
                # UDP
                #self.__udp_packets.append(eth)
                udp=ip.data
                port1=udp.sport
                port2=udp.dport
                (c,conv)=self.__match_conversation(ipquad1,port1,ipquad2,port2,u"udp")
                if c=='?':
                    if (port1 in self.__well_known_udp):
                        ips=ipquad2
                        ipd=ipquad1
                        port=port1
                    elif (port2 in self.__well_known_udp):
                        ips=ipquad1
                        ipd=ipquad2
                        port=port2
                    else:
                        self.__orphan_packets.append(eth)
                        return "Not added"
                    self.add_conv(ips,ipd,u"udp",port,packet_size)
                    return "UDP"
                else:
                    conv.packets+=1
                    conv.bytes+=packet_size
                    self.dbsession.flush()
                    return c

                #id1=self.__add_endpoint(ipquad1,port1)
                #id2=self.__add_endpoint(ipquad2,port2)
                #conn=self.__add_connection(id1,id2)


    def add_ip(self, ipa, mac=u""):
        """Adds an IP address to the current capture"""
        #if self.dbsession.query(ip).filter(ip.ip==ipa,ip.capture_id==self.dbcapture.id).count()>0:
        a=self.dbsession.query(ip).filter(ip.ip==ipa,ip.capture_id==self.dbcapture.id).all()
        if len(a)>0:
            # Already exists
            return a[0]
        else:
            ip1 = ip(ip=ipa, mac=mac, capture_id=self.dbcapture.id)
            self.dbsession.add(ip1)
            self.dbsession.flush()
            #self.dbsession.commit()
            return ip1


    def add_conv(self,ips,ipd,proto,port,packet_size):
        """Adds a conversation to the current capture"""
        #if self.dbsession.query(conversation).filter(conversation.ipsrc_ip==ips, conversation.ipdst_ip==ipd, \
        #                                             conversation.proto==proto, conversation.port==port, \
        #                                              conversation.capture_id==self.dbcapture.id).count()>0:
        a=self.dbsession.query(conversation).filter(conversation.ipsrc_ip==ips, conversation.ipdst_ip==ipd, \
                                                     conversation.proto==proto, conversation.port==port, \
                                                      conversation.capture_id==self.dbcapture.id).all()
        if len(a)>0:
            # Already exists
            return a[0]
        else:
            conv1=conversation(ipsrc_ip=ips,ipdst_ip=ipd,proto=proto,port=port, \
                               capture_id=self.dbcapture.id,packets=1,bytes=packet_size)
            self.dbsession.add(conv1)
            self.dbsession.flush()
            #self.dbsession.commit()
            return conv1



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

    def __match_conversation(self,ip1,port1,ip2,port2,proto):
        possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                      conversation.proto==proto, \
                                      conversation.ipsrc_ip==ip2, \
                                      conversation.ipdst_ip==ip1, \
                                      conversation.port==port1).all()
        if len(possconv)==1:
            # found matching conversation
            return ('>',possconv[0])
        else:
            possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                      conversation.proto==proto, \
                                      conversation.ipsrc_ip==ip1, \
                                      conversation.ipdst_ip==ip2, \
                                      conversation.port==port2).all()
            if len(possconv)==1:
                # found match in the other direction
                return ('<',possconv[0])
            else:
                # Conversation not found
                return ('?',None)

    def __add_endpoint(self,ip,port):
        a=self.dbsession.query(endpoint).filter(endpoint.ip==ip, endpoint.port==port).all()
        if len(a)>0:
            return a[0].id
        else:
            ep=endpoint(ip=ip,port=port)
            self.dbsession.add(ep)
            self.dbsession.flush()
            return ep.id

    def __add_connection(self,id1,id2):
        if self.dbsession.query(connection).filter(connection.ipsrc_id==id1,connection.ipdst_id==id2).count()>0:
            return 0
        else:
            co=connection(ipsrc_id=id1,ipdst_id=id2)
            self.dbsession.add(co)
            self.dbsession.flush()
            return 1
