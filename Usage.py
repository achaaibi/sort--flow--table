from db_conf import Base
from sqlalchemy import Column, String, Integer


class Usage(Base):
    # Table's name in the db
    __tablename__ = 'usage'

    id = Column(Integer, primary_key=True)
    ip = Column(String)
    usage = Column(String)

    # Constructor
    def __init__(self, ip, usage):
        self.ip = ip
        self.usage = usage
