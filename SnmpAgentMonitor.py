import json

from pysnmp.hlapi import *
import rrdtool
import uuid
import sqlite3
import sys
import time
from enum import Enum
from sqlite3 import Error
import threading


class SNMPObjectId():
    # ifInOctets
    INPUT_TRAFFIC = '1.3.6.1.2.1.2.2.1.10'
    # ifInUcastPkts
    # 1) Paquetes unicast que ha recibido una interfaz
    INPUT_UNICAST = '1.3.6.1.2.1.2.2.1.11'
    # ipInReceives
    # 1) Paquetes recibidos a protocolos IPv4, incluyendo los que tienen errores.
    INPUT_IP_PACKAGES = '1.3.6.1.2.1.4.3.0'
    # icmpOutEchos
    # 1) Mensajes ICMP echo que ha enviado el agente
    OUTPUT_ICMP_ECHOS = '1.3.6.1.2.1.5.21.0'
    # tcpInSegs
    # 1) Segmentos recibidos, incluyendo los que se han recibido con errores.
    INPUT_TCP_SEGMENTS_COUNTER = '1.3.6.1.2.1.6.10.0'
    # udpInDatagrams
    # 1) Datagramas entregados a usuarios UDP
    INPUT_UDP_DATAGRAMS_COUNTER = '1.3.6.1.2.1.7.1.0'
    # system description
    SYS_TYPE = '1.3.6.1.2.1.1.1.0'
    SYS_SNMP_V = '1.3.6.1.2.1.1.2.0'
    SYS_NAME = '1.3.6.1.2.1.1.5.0'
    SYS_UPTIME = '1.3.6.1.2.1.1.3.0'
    SYS_LOCATION = '1.3.6.1.2.1.1.6.0'

    # interfaces
    INTERFACES_NUMBER = '1.3.6.1.2.1.2.1.0'
    INTERFACE_NAME = '1.3.6.1.2.1.2.2.1.2'
    INTERFACE_TYPE = '1.3.6.1.2.1.2.2.1.3'
    INTERFACE_STATUS = '1.3.6.1.2.1.2.2.1.7'


class InterfaceData:
    STATUS: str = ""
    DESCRIPTION: str = ""

    def __repr__(self):
        return {
            "DESCRIPTION": self.DESCRIPTION,
            "STATUS": self.STATUS
        }

    def to_json(self):
        return {
            "DESCRIPTION": self.DESCRIPTION,
            "STATUS": self.STATUS
        }
    def __str__(self):
        return f"Description: {self.DESCRIPTION}\nStatus: {self.STATUS}\n"

    def __init__(self, status: str, description: str):
        self.STATUS = status
        self.DESCRIPTION = description


class SNMPAgent:
    agent_id: int = 0
    agent_ip_address: str = ""
    rdd_file: str = ""
    port: int = 0
    snmp_version: int = 0
    community_name: str = ""
    STATUS: str = ""
    agent_name: str = ""
    agent_location: str = ""
    agent_version: str = ""
    agent_os_logo: str = ""
    agent_ports_number: str = ""
    agent_agent_name: str = ""
    agent_agent_sys: str = ""
    agent_uptime: int = 0
    INTERFACES_NUMBER: int = 0
    INTERFACES: list[InterfaceData] = []

    def __repr__(self):
        return {
            "agent_id": self.agent_id,
            "agent_ip_address": self.agent_ip_address,
            "rdd_file": self.rdd_file,
            "port": self.port,
            "snmp_version": self.snmp_version,
            "community_name": self.community_name,
            "STATUS": self.STATUS,
            "agent_name": self.agent_name,
            "agent_location": self.agent_location,
            "agent_version": self.agent_version,
            "agent_os_logo": self.agent_os_logo,
            "agent_ports_number": self.agent_ports_number,
            "agent_agent_name": self.agent_agent_name,
            "agent_agent_sys": self.agent_agent_sys,
            "agent_uptime": self.agent_uptime,
            "INTERFACES_NUMBER": self.INTERFACES_NUMBER,
            "INTERFACES": self.INTERFACES
        }

    def to_json(self):
        return {
            "agent_id": self.agent_id,
            "agent_ip_address": self.agent_ip_address,
            "rdd_file": self.rdd_file,
            "port": self.port,
            "snmp_version": self.snmp_version,
            "community_name": self.community_name,
            "STATUS": self.STATUS,
            "agent_name": self.agent_name,
            "agent_location": self.agent_location,
            "agent_version": self.agent_version,
            "agent_os_logo": self.agent_os_logo,
            "agent_ports_number": self.agent_ports_number,
            "agent_agent_name": self.agent_agent_name,
            "agent_agent_sys": self.agent_agent_sys,
            "agent_uptime": self.agent_uptime,
            "INTERFACES_NUMBER": self.INTERFACES_NUMBER,
            "INTERFACES": [interface.to_json() for interface in self.INTERFACES]
        }
    def __str__(self):
        str_representation = f"Agent ID: {self.agent_id} \n" \
                             f"Agent IP Address: {self.agent_ip_address}\n" \
                             f"Agent IP Address: {self.agent_ip_address}\n" \
                             f"Agent System: {self.agent_agent_sys}\n" \
                             f"Agent System Name: {self.agent_agent_name}\n" \
                             f"Agent System Location: {self.agent_location}\n" \
                             f"Agent Uptime: {self.agent_uptime}" \
                             f"Agent Interfaces Count: {self.INTERFACES_NUMBER}\n"
        interfaces = f"Agent Interfaces: {[str(interface) for interface in self.INTERFACES]}\n"
        return str_representation

    def __init__(self, address: str, port: int, snmp_version: int, community_name: str, agent_file_name: str,
                 agent_id: int = 0):
        self.agent_ip_address = address
        self.port = port
        self.snmp_version = snmp_version
        self.community_name = community_name
        self.rdd_file = agent_file_name
        self.agent_id = agent_id


class SNMPUtils:

    def snmp_query(self, community_name, host, oid):
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                   CommunityData(community_name),
                   UdpTransportTarget((host, 161)),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid))))
        result = None
        if error_indication:
            print(error_indication)
        elif error_status:
            print('%s at %s' % (error_status.prettyPrint(), error_index and var_binds[int(error_index) - 1][0] or '?'))
        else:
            for varBind in var_binds:
                var_b = (' = '.join([x.prettyPrint() for x in varBind]))
                result = var_b.split()[2]
        return result

    def _update_interface_data(self, agent, interface_index: int):
        name = self.snmp_query(agent.community_name, agent.agent_ip_address,
                               f'{SNMPObjectId.INTERFACE_NAME}.{interface_index}')
        _raw_status = int(self.snmp_query(agent.community_name, agent.agent_ip_address,
                                          f'{SNMPObjectId.INTERFACE_STATUS}.{interface_index}'))
        status = "up" if _raw_status == 1 else "down" if _raw_status == 2 else "test"
        return InterfaceData(status, name)

    def update(self, agent: SNMPAgent):
        agent.INTERFACES_NUMBER = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address,
                            SNMPObjectId.INTERFACES_NUMBER))
        agent.INTERFACES = [self._update_interface_data(agent, i) for i in range(1, agent.INTERFACES_NUMBER + 1)]
        agent.snmp_version = self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.SYS_SNMP_V)
        agent.agent_name = self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.SYS_NAME)
        agent.agent_agent_name = self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.SYS_NAME)
        agent.agent_agent_sys = self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.SYS_TYPE)
        agent.agent_uptime = self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.SYS_UPTIME)
        agent.agent_location = self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.SYS_LOCATION)
        input_unicast_traffic = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, f'{SNMPObjectId.INPUT_UNICAST}.2'))
        input_ip_traffic = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.INPUT_IP_PACKAGES))
        output_icmp_echos = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.OUTPUT_ICMP_ECHOS))
        input_tcp_segments = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.INPUT_TCP_SEGMENTS_COUNTER))
        input_udp_segments = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, SNMPObjectId.INPUT_UDP_DATAGRAMS_COUNTER))
        rrd_value = f"N:{input_unicast_traffic}:{input_ip_traffic}:{output_icmp_echos}:{input_tcp_segments}:{input_udp_segments}"
        rrdtool.update(agent.rdd_file, rrd_value)
        rrdtool.dump(agent.rdd_file, f"{agent.rdd_file.split('.')[0]}.xml")
        time.sleep(1)


def create_rdd_file(agent_file_name):
    try:
        ret = rrdtool.create(agent_file_name,
                             "--start", 'N',
                             "--step", '60',
                             "DS:inputunicast:COUNTER:600:U:U",
                             "DS:inputip:COUNTER:600:U:U",
                             "DS:outputicmp:COUNTER:600:U:U",
                             "DS:inputtcp:COUNTER:600:U:U",
                             "DS:inputudp:COUNTER:600:U:U",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5")
        if ret:
            print(rrdtool.error())
    except Exception as e:
        print(">> ERROR AT RDD FILE CREATION:", e)


class SNMPMonitor:
    AGENTS: list[SNMPAgent] = []
    _sqlite_con = None
    _sqlite_cursor = None
    _stop_threads = False

    # >> S Q L I T E  ~ SECTION
    def _init_db(self):
        self._sqlite_con = sqlite3.connect('SnmpDatabase.db')
        self._sqlite_cursor = self._sqlite_con.cursor()
        self._sqlite_cursor.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='AGENTS';")
        b_create_table = self._sqlite_cursor.fetchone()[0]
        if b_create_table == 0:
            createstr = "CREATE TABLE AGENTS(id INTEGER PRIMARY KEY AUTOINCREMENT,agent_ip_address TEXT NULL,rdd_file TEXT NULL,port INTEGER NULL,snmp_version TEXT NULL,community_name TEXT NULL,active INTEGER NULL)"
            self._sqlite_cursor.execute(createstr)

    def _insert_sqlite_agent(self, agent: SNMPAgent):
        try:
            self._sqlite_cursor.execute("INSERT INTO AGENTS("
                                        + "agent_ip_address, "
                                        + "rdd_file,"
                                        + "port, "
                                        + "snmp_version,"
                                        + "community_name,"
                                        + "active) "
                                        + "VALUES (?,?,?,?,?,?)", (
                                            agent.agent_ip_address,
                                            agent.rdd_file,
                                            agent.port,
                                            agent.snmp_version,
                                            agent.community_name, 1))
            self._sqlite_con.commit()
        except Error as e:
            print(e)

    def _delete_sqlite_agent(self, agent: SNMPAgent):
        query = f"UPDATE AGENTS SET active=0 WHERE id={agent.agent_id}"
        self._sqlite_cursor.execute(query)
        self._sqlite_con.commit()

    def _load_sqlite_agents(self):
        self._sqlite_cursor.execute('SELECT * FROM AGENTS WHERE active=1;')
        agents = self._sqlite_cursor.fetchall()
        self.AGENTS = [SNMPAgent(agent_id=a[0], address=a[1], agent_file_name=a[2], port=a[3], snmp_version=a[4],
                                 community_name=a[5]) for a in agents]

    # AGENTS TEMPLATE:
    # {"STATUS":0, "INTERFACES_NUMBER":0,"INTERFACES":[{"STATUS":"","DESCRIPTION":""}]}\
    def add_agent(self, direction, port, snmp_version, community_name):
        agent_file_name = f"{direction}_{port}_SNMP{snmp_version}_{community_name}_{uuid.uuid4()}.rdd"
        create_rdd_file(agent_file_name)
        agent = SNMPAgent(direction, port, snmp_version, community_name, agent_file_name)
        self.AGENTS.append(agent)
        self._insert_sqlite_agent(agent)
        return agent

    def monitor_agents(self):
        snmp_obj = SNMPUtils()
        while not self._stop_threads:
            for agent in self.AGENTS:
                snmp_obj.update(agent)

    def remove_agent(self, agent_id: int):
        agent = next((agent for agent in self.AGENTS if agent.agent_id == agent_id))
        if agent:
            self._delete_sqlite_agent(agent)
            self.AGENTS.remove(agent)

        return "success"

    def export_current_data(self):
        filename = f"{uuid.uuid4()}.json"
        with open(filename, 'w') as outfile:
            try:
                json_data = [agent.to_json() for agent in self.AGENTS]
                print(json_data)
                json.dump(json_data, outfile)
            except Exception as e:
                print(e)
        return filename

    def close(self):
        self._sqlite_con.close()
        self._stop_threads = True

    def __init__(self):
        try:
            self._init_db()
            self._load_sqlite_agents()
            x = threading.Thread(target=self.monitor_agents)
            x.start()

        except Error as e:
            print(e)
            print("Expurosion! ", sys.exc_info()[0])
