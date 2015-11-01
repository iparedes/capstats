__author__ = 'nacho'

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, BigInteger,String, ForeignKey, Unicode, Binary, LargeBinary, Time, DateTime, Date, Text, Boolean
from sqlalchemy.orm import relationship, backref, deferred
from sqlalchemy.orm import sessionmaker

Base=declarative_base()

class capture (Base):
    __tablename__ = "capture"
    id = Column('id', Integer, primary_key = True)
    description = deferred(Column('Description', Text))
    ips=relationship("ip",backref="capture")
    conversations=relationship("conversation",backref="capture")


class ip(Base):
    __tablename__ = "ip"
    #id = Column('id', Integer, primary_key = True)
    mac = Column('mac', Unicode)
    ip = Column('ip', Unicode,primary_key=True)
    capture_id=Column(Integer,ForeignKey('capture.id'),primary_key=True)
    convsrc=relationship('conversation',backref=backref('ip'),primaryjoin="conversation.ipsrc_ip==ip.ip")
    convdst=relationship('conversation',primaryjoin="conversation.ipdst_ip==ip.ip")

class conversation(Base):
    __tablename__="conversation"
    port = Column('port',Integer,primary_key=True)
    proto = Column('proto',Unicode,primary_key=True)
    capture_id=Column(Integer,ForeignKey('capture.id'),primary_key=True)
    ipsrc_ip=Column(Unicode,ForeignKey('ip.ip'),primary_key=True)
    ipdst_ip=Column(Unicode,ForeignKey('ip.ip'),primary_key=True)


