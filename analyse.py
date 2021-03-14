import json
from sqlalchemy import func, case, insert
import logging
import requests
import pandas as pd
from sqlalchemy.orm import aliased

from Usage import Usage
from netaddr import iter_iprange
from db_conf import Session, engine, Base
from FlowTable import FlowTable
from AnalysedFlow import AdvancedFlow
from AnalysedFlow import AnalysedFlow
from CSVAdeo import CSVAdeo

logging.basicConfig(filename='example.log', level=logging.INFO)

Base.metadata.create_all(engine)
config_file = open('./.config.json', "r")
config = json.load(config_file)

IPAM_LOGIN = config["ipam_login"]
IPAM_PASSWORD = config["ipam_password"]
IPAM_HOSTNAME = config["ipam_hostname"]
CERTPATH = config["certpath"]
DB_IPAM_REFRESH = False


def get_ipam_data():
    r = requests.get(
        "https://" + IPAM_LOGIN + ":" + IPAM_PASSWORD + "@" + IPAM_HOSTNAME + "/wapi/v2.4/range?_return_fields=extattrs,start_addr,end_addr&_return_type=json&_max_results=-100000",
        verify=CERTPATH)
    data = json.loads(r.text)
    return data


if DB_IPAM_REFRESH is True:
    session = Session()
    data = get_ipam_data()
    i = 0
    for range_ipam in data:
        if 'extattrs' in range_ipam:
            if 'usage' in range_ipam["extattrs"]:
                ip_list = list(iter_iprange(range_ipam["start_addr"], range_ipam["end_addr"]))
                for ip in ip_list:
                    is_in_db = session.query(Usage).filter(Usage.ip == str(ip)).count()
                    if is_in_db == 0:
                        usage = Usage(str(ip), str(range_ipam["extattrs"]["usage"]["value"]))
                        session.add(usage)
                        session.commit()
                        print(str(i) + " added to db")
                        i = i + 1
    session.close()


def get_csv_ip(file_name):
    # Load CSV to csv_file table
    df = pd.read_csv(file_name, usecols=[0,1,2,3,4,5], sep=',', quotechar='\'',
                     encoding='utf8', error_bad_lines=False)
    result = pd.DataFrame(df)
    return result


def get_csv(file_name):
    # Load CSV to csv_file table
    df = pd.read_csv(file_name, usecols=[0, 1, 2, 3, 4, 5, 9, 10], sep=',', quotechar='\'',
                     encoding='utf8', error_bad_lines=False)
    result = pd.DataFrame(df)
    return result


def add_ip_to_db():
    session = Session()
    j = 0
    file_name = "matrice.csv"
    data = get_csv_ip(file_name)
    while j < 1:
        for i in data.itertuples():
            usage_source = i[1]
            usage_destination = i[2]
            protocol = i[3]
            application = i[4]
            vlan_destination = i[5]
            state = i[6]
            to_add = AnalysedFlow(usage_source,usage_destination, protocol, application,vlan_destination,state)
            session.add(to_add)
            session.commit()
        j = j + 1
    session.close()


def add_csv_to_db():
    session = Session()
    j = 0
    file_name = "ADEO_DASHBOARD.csv"
    data = get_csv(file_name)
    while j < 1:
        for i in data.itertuples():
            hostname = i[1]
            ip = i[2]
            network_comment = i[3]
            type_info = i[4]
            network = i[5]
            gateway = i[6]
            zone = i[7]
            bu = i[8]
            to_add = CSVAdeo(hostname, ip, network_comment, type_info, network, gateway, zone, bu)
            session.add(to_add)
            session.commit()
        j = j + 1
    session.close()


def analysed_flow(vlan_list):
    # La requête a besoin d'un join avec la table Usage 2 fois --> alias
    session = Session()
    dst = aliased(Usage)
    src = aliased(Usage)
    # Expressions SQL
    usage = func.coalesce(dst.usage, FlowTable.ip_destination)
    usage_ip_src = func.coalesce(src.usage, FlowTable.ip_source)
    protocol = case({"17": "UDP",
                     "1": "ICMP",
                     "6": "TCP"},
                    value=FlowTable.protocol,
                    else_=FlowTable.protocol)
    # Requête SQL qui cherche les données à ajouter dans la table AnalysedFlow
    flows = session.query(
        usage_ip_src,
        usage,
        protocol,
        FlowTable.application,
        FlowTable.destination_port,
        FlowTable.vlan_destination,
        FlowTable.state). \
        outerjoin(dst, dst.ip == FlowTable.ip_destination). \
        outerjoin(src, src.ip == FlowTable.ip_source). \
        filter(FlowTable.vlan_destination.in_(vlan_list),
               ~session.query(AnalysedFlow).
               filter_by(usage_source=usage_ip_src,
                         usage_destination=usage,
                         protocol=protocol,
                         application=FlowTable.application,
                         destination_port=FlowTable.destination_port,
                         vlan_destination=FlowTable.vlan_destination,
                         state=FlowTable.state).
               exists())
    flows = flows.distinct()
    stmt = insert(AnalysedFlow).from_select(
        ["usage_source", "usage_destination", "protocol", "application",
         "destination_port", "vlan_destination", "state"],
        flows)
    session.execute(stmt)
    session.commit()
    return session.execute(stmt)


def advanced_flow():
    # add_csv_to_db()
    session = Session()
    i = 0
    start_id = 1
    flows = session.query(AnalysedFlow).filter(AnalysedFlow.id >= start_id).all()
    type_list = {"NET", "FOLD", "HOST", "A"}
    result_number = len(flows)
    while i < result_number:
        for flow in flows:
            usage = session.query(CSVAdeo).filter(CSVAdeo.ip == str(flow.usage_source)).all()
            if len(usage) > 0:
                hostname = usage[0].hostname
                network_comment = usage[0].network_comment
                type_info = usage[0].type_info
                network = usage[0].network
                gateway = usage[0].gateway
                zone = usage[0].zone
                bu = usage[0].bu
            else:
                hostname = str("unknown")
                type_info = str("unknown")
                network_comment = str("unknown")
                network = str("unknown")
                gateway = str("unknown")
                zone = str("unknown")
                bu = str("unknown")
            is_in_db = session.query(AdvancedFlow) \
                .filter(AdvancedFlow.protocol == flow.protocol) \
                .filter(AdvancedFlow.application == flow.application) \
                .filter(AdvancedFlow.vlan_destination == flow.vlan_destination) \
                .filter(AdvancedFlow.usage_source == flow.usage_source) \
                .filter(AdvancedFlow.state == flow.state) \
                .filter(AdvancedFlow.usage_destination == flow.usage_destination) \
                .filter(AdvancedFlow.hostname == hostname) \
                .filter(AdvancedFlow.network_comment == network_comment) \
                .filter(AdvancedFlow.type_info == type_info) \
                .filter(AdvancedFlow.network == network) \
                .filter(AdvancedFlow.gateway == gateway) \
                .filter(AdvancedFlow.zone == zone) \
                .filter(AdvancedFlow.bu == bu).count()
            if type_info in type_list:
                if is_in_db == 0:
                    to_add = AdvancedFlow(flow.usage_source, hostname, network_comment, type_info,
                                          network, gateway, zone, bu, flow.usage_destination, flow.protocol,
                                          flow.application, flow.vlan_destination,
                                          flow.state)
                    session.add(to_add)
                    session.flush()
                    session.commit()
                    start_id = flow.id
                    print("added " + str(i))
                else:
                    print("usage already in DB")
            else:
                type_info = 'CNAM'
                if is_in_db == 0:
                    to_add = AdvancedFlow(flow.usage_source, hostname, network_comment, type_info,
                                          network, gateway, zone, bu, flow.usage_destination, flow.protocol,
                                          flow.application, flow.vlan_destination,
                                          flow.state)
                    session.add(to_add)
                    session.flush()
                    session.commit()
                    start_id = flow.id
                    print("added " + str(i))
                else:
                    print("usage already in DB")
            i = i + 1
        session.close()


def run_analyse():
    advanced_flow()
    print("script done")


run_analyse()
