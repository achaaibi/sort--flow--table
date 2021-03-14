from db_conf import Base
from sqlalchemy import Column, String, Integer


class AnalysedFlow(Base):
    # Table's name in the db
    __tablename__ = 'analysed_flow'

    id = Column(Integer, primary_key=True)
    usage_source = Column(String)
    usage_destination = Column(String)
    protocol = Column(String)
    application = Column(String)
    destination_port = Column(Integer)
    vlan_destination = Column(String)
    state = Column(String)

    # Constructor
    def __init__(self, usage_source, usage_destination,  protocol,
                 application, destination_port, vlan_destination, state):
        self.usage_source = usage_source
        self.usage_destination = usage_destination
        self.protocol = protocol
        self.application = application
        self.destination_port = destination_port
        self.vlan_destination = vlan_destination
        self.state = state


class AdvancedFlow(Base):
    # Table's name in the db
    __tablename__ = 'advanced_flow'

    id = Column(Integer, primary_key=True)
    usage_source = Column(String)
    hostname = Column(String)
    network_comment = Column(String)
    type_info = Column(String)
    network = Column(String)
    gateway = Column(String)
    zone = Column(String)
    bu = Column(String)
    usage_destination = Column(String)
    protocol = Column(String)
    application = Column(String)
    destination_port = Column(Integer)
    vlan_destination = Column(String)
    state = Column(String)

    # Constructor
    def __init__(self, usage_source, hostname, network_comment, type_info, network,
                 gateway, zone, bu, usage_destination, protocol,
                 application, destination_port, vlan_destination, state):
        self.usage_source = usage_source
        self.hostname = hostname
        self.network_comment = network_comment
        self.type_info = type_info
        self.network = network
        self.gateway = gateway
        self.zone = zone
        self.bu = bu
        self.usage_destination = usage_destination
        self.protocol = protocol
        self.application = application
        self.destination_port = destination_port
        self.vlan_destination = vlan_destination
        self.state = state