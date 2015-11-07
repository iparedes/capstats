__author__ = 'nacho'

import dpkt
import socket
import binascii
import sys

from cap_model import *

from sqlalchemy import exc,MetaData,Table



class Capture():
    def __init__(self):
        engine = create_engine('sqlite:///orm_in_detail.sqlite')
        Session = sessionmaker()
        Session.configure(bind=engine)
        self.dbsession=Session()
        self.orphan_packets=[]
        self.__udp_packets=[]
        Base.metadata.create_all(engine)
        self.__well_known_udp=(53,67,69,79,88,113,119,123,135,137,138,139,161,162)

    def open(self, fich):
        try:
            f = open(fich, "r")
            self.pcap = dpkt.pcap.Reader(f)
            self.npackets = len(list(self.pcap))
            self.processed_packets=0


            self.dbcapture = capture(filename=fich)
            self.dbsession.add(self.dbcapture)
            self.dbsession.flush()
            self.dbsession.commit()

            return 1
        except IOError:
            return 0



    def analyze_packet(self, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        self.processed_packets+=1
        packet_size=len(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # IP packet
            ip = eth.data
            mac1=unicode(eth.src.encode('hex'))
            mac2=unicode(eth.dst.encode('hex'))
            ipquad1 = unicode(socket.inet_ntoa(ip.src))
            ipquad2 = unicode(socket.inet_ntoa(ip.dst))
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                # TCP
                tcp = ip.data
                port1=tcp.sport
                port2=tcp.dport
                if ((tcp.flags & dpkt.tcp.TH_SYN) != 0) and ((tcp.flags & dpkt.tcp.TH_ACK) == 0):
                    # Start of 3-way handshake
                    self.add_ip(ipquad1,mac1)
                    self.add_ip(ipquad2,mac2)
                    self.add_conv(ipquad1,ipquad2,u"tcp",port2,packet_size)
                    #return ipquad1+","+ipquad2
                    return "TCP"
                else:
                    # Conversation started previous to the capture
                    (c,conv)=self.__match_conversation(ipquad1,port1,ipquad2,port2,u"tcp")
                    if (c=='?'):
                        # Conversation not found
                        if self.__is_multicast(ipquad2):
                            # If multicast assume the destination as the server in the conversation
                            ips=ipquad1
                            ipd=ipquad2
                            port=port2
                        else:
                            self.orphan_packets.append(buf)
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
                    # New conversation
                    if (port1 in self.__well_known_udp):
                        ips=ipquad2
                        ipd=ipquad1
                        port=port1
                    elif (port2 in self.__well_known_udp):
                        ips=ipquad1
                        ipd=ipquad2
                        port=port2
                    else:
                        # Not identified protocol
                        if self.__is_multicast(ipquad2):
                            ips=ipquad1
                            ipd=ipquad2
                            port=port2
                        else:
                            self.orphan_packets.append(buf)
                            return "Not added"
                    self.add_conv(ips,ipd,u"udp",port,packet_size)
                    return "UDP"
                else:
                    # Previously identified conversation
                    conv.packets+=1
                    conv.bytes+=packet_size
                    self.dbsession.flush()
                    return c

                #id1=self.__add_endpoint(ipquad1,port1)
                #id2=self.__add_endpoint(ipquad2,port2)
                #conn=self.__add_connection(id1,id2)

    def analyze_orphans(self):
        servers=self.servers()
        lista=list(self.orphan_packets)
        for buf in lista:
            packet_size=len(buf)
            eth=dpkt.ethernet.Ethernet(buf)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # IP packet
                ip = eth.data
                mac1=unicode(eth.src.encode('hex'))
                mac2=unicode(eth.dst.encode('hex'))
                ipquad1 = unicode(socket.inet_ntoa(ip.src))
                ipquad2 = unicode(socket.inet_ntoa(ip.dst))
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    # TCP
                    tcp = ip.data
                    port1=tcp.sport
                    port2=tcp.dport
                    (c,conv)=self.__match_conversation(ipquad1,port1,ipquad2,port2,u"tcp")
                    if (c=='?'):
                        #still orphan
                        if (ipquad1,port1,u"tcp") in servers:
                            self.add_conv(ipquad2,ipquad1,u"tcp",port1,packet_size)
                            self.orphan_packets.remove(buf)
                        elif (ipquad2,port2,u"tcp") in servers:
                            self.add_conv(ipquad1,ipquad2,u"tcp",port2,packet_size)
                            self.orphan_packets.remove(buf)
                        else:
                            # still missing
                            a=1
                            pass
                    else:
                        conv.packets+=1
                        conv.bytes+=len(buf)
                        self.dbsession.flush()
                        self.orphan_packets.remove(buf)
                else:
                    # Not TCP
                    a=2
                    pass
# La primera pasada anade a las conversaciones que ya existen
# La segunda pasada debe identificar servidores y crear nuevas conversaciones basado en esto

    def count_orphan_ports(self):
        self.orphan_tcps=dict()
        self.orphan_udps=dict()
        for buf in self.orphan_packets:
            packet_size=len(buf)
            eth=dpkt.ethernet.Ethernet(buf)
            if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # IP packet
                ip = eth.data
                data=ip.data
                port1=data.sport
                port2=data.dport
                if ip.p == dpkt.ip.IP_PROTO_TCP:
                    # TCP
                    l=self.orphan_tcps
                elif ip.p==dpkt.ip.IP_PROTO_UDP:
                    l=self.orphan_udps
                else:
                    continue
                if port1 in l:
                    l[port1]+=1
                else:
                    l[port1]=1
                if port2 in l:
                    l[port2]+=1
                else:
                    l[port2]=1


    def add_ip(self, ipa, mac):
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

    def servers(self):
        p=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id).all()
        servers=[]
        for i in p:
            servers.append((i.ipdst_ip,i.port,i.proto))
        return servers



    def orphans(self):
        orphan_list=[]
        self.odds=[]
        for buf in self.orphan_packets:
            i=dpkt.ethernet.Ethernet(buf)
            if i.type == dpkt.ethernet.ETH_TYPE_IP:
                # IP packet
                ip = i.data
                mac1=unicode(i.src.encode('hex'))
                mac2=unicode(i.dst.encode('hex'))
                ipquad1 = unicode(socket.inet_ntoa(ip.src))
                ipquad2 = unicode(socket.inet_ntoa(ip.dst))
                data= ip.data
                port1=data.sport
                port2=data.dport
                orphan_list.append((mac1,ipquad1,port1,mac2,ipquad2,port2,ip.p))
            else:
                # Not ethernet. This should probably be in analyze_packet
                self.odds.append(i)
        return (orphan_list,self.odds)

# Check if any of the IP:port corresponds to a conversation end (server)
# Check if any of the IP is multicast -> sets conversation


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

    def __is_multicast(self,quadip):
        a=int(quadip.split('.')[0])
        if a>=224 and a<=239:
            return True
        else:
            return False




    def __match_conversation(self,ip1,port1,ip2,port2,proto):
        possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                      conversation.proto==proto, \
                                      conversation.ipsrc_ip==ip2, \
                                      conversation.ipdst_ip==ip1, \
                                      conversation.port==port1).all()
        if len(possconv)==1:
            # found matching conversation
            return ('<',possconv[0])
        else:
            possconv=self.dbsession.query(conversation).filter(conversation.capture_id==self.dbcapture.id, \
                                      conversation.proto==proto, \
                                      conversation.ipsrc_ip==ip1, \
                                      conversation.ipdst_ip==ip2, \
                                      conversation.port==port2).all()
            if len(possconv)==1:
                # found match in the other direction
                return ('>',possconv[0])
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

    def __add_colons_to_mac(self, mac_addr ) :
        """This function accepts a 12 hex digit string and converts it to a colon separated string"""
        s = list()
        for i in range(12/2) : 	# mac_addr should always be 12 chars, we work in groups of 2 chars
            s.append( mac_addr[i*2:i*2+2] )
        r = ":".join(s)		# I know this looks strange, refer to http://docs.python.org/library/stdtypes.html#sequence-types-str-unicode-list-tuple-bytearray-buffer-xrange
        return r


