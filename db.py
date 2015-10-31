__author__ = 'nacho'


from cap_model import *
from sqlalchemy import exc

engine = create_engine('sqlite:///orm_in_detail.sqlite')
Session = sessionmaker()
Session.configure(bind=engine)
sess=Session()
Base.metadata.create_all(engine)

dbcapture=capture()
sess.add(dbcapture)
sess.flush()

try:
    ip1=ip(ip=u"1.2.3.4",mac=u"w",capture_id=dbcapture.id)
    ip2=ip(ip=u"2.3.4.5",mac=u"x",capture_id=dbcapture.id)


    sess.add(ip1)
    sess.add(ip2)

    #dbcapture.ips.append(ip1)
    #dbcapture.ips.append(ip2)

    sess.flush()
    sess.commit()

    ip3=ip(ip=u"2.3.4.5")
    sess.add(ip3)
    #dbcapture.ips.append(ip3)
    sess.flush()
    sess.commit()
except exc.SQLAlchemyError:
    pass