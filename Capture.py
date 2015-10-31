__author__ = 'nacho'

import dpkt
import socket
import cap_model

from sqlalchemy import exc



class Capture():
    def __init__(self, dbsession):
        self.dbsession = dbsession

    def open(self, fich):
        try:
            f = open(fich, "r")
            self.pcap = dpkt.pcap.Reader(f)
            self.npackets = len(list(self.pcap))

            self.dbcapture = cap_model.capture()
            self.dbsession.add(self.dbcapture)
            self.dbsession.flush()
            self.dbsession.commit()

            return 1
        except IOError:
            return 0

    def analyze_packet(self, buf):
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            # IP packet
            ip = eth.data
            if ip.p == dpkt.ip.IP_PROTO_TCP:
                # TCP
                tcp = ip.data
                if ((tcp.flags & dpkt.tcp.TH_SYN) != 0) and ((tcp.flags & dpkt.tcp.TH_ACK) == 0):
                    # Start of 3-way handshake
                    ipquad1 = socket.inet_ntoa(ip.src)
                    self.add_ip(ipquad1)
                    ipquad2 = socket.inet_ntoa(ip.dst)
                    self.add_ip(ipquad2)
                    return ipquad1+","+ipquad2
                else:
                    # Conversation started previous to the capture
                    return "Not added"

    def add_ip(self, ipa, mac=u""):
        try:
            ip1 = cap_model.ip(ip=ipa, mac=mac, capture_id=self.dbcapture.id)
            self.dbsession.add(ip1)

            self.dbsession.flush()
            self.dbsession.commit()
            return 1
        except exc.SQLAlchemyError:
            return 0