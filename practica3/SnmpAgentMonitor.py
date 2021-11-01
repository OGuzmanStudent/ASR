import json
import sqlite3
import sys
import threading
import time
import uuid
from datetime import datetime
from sqlite3 import Error

import pdfkit
import rrdtool
from pysnmp.hlapi import *


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

    # Host data
    TOTAL_RAM_MEMORY_LINUX = 'iso.3.6.1.4.1.2021.4.5.0'
    USED_RAM_MEMORY_LINUX = 'iso.3.6.1.4.1.2021.4.6.0'

    TOTAL_RAM_MEMORY_WINBUS = "1.3.6.1.2.1.25.2.3.1.5.4"
    USED_RAM_MEMORY_WINBUS = "1.3.6.1.2.1.25.2.3.1.6.4"
    RAM_BUFFER_SIZE = "1.3.6.1.2.1.25.2.3.1.4.4"

    PROCESSOR_USAGE_LINUX = "iso.3.6.1.2.1.25.3.3.1.2.196608"
    PROCESSOR_USAGE_WINBUS = "iso.3.6.1.2.1.25.3.3.1.2.4"

    TOTAL_DISK_WINDOWS = "iso.3.6.1.2.1.25.2.3.1.5.1"
    DISK_BYTES_PER_UNIT_WINDOWS = "iso.3.6.1.2.1.25.2.3.1.5.1"
    DISK_USAGE_WINDOWS = "iso.3.6.1.2.1.25.2.3.1.5.1"

    TOTAL_DISK_LINUX = "iso.3.6.1.2.1.25.2.3.1.5.63"
    DISK_BYTES_PER_UNIT_LINUX = "iso.3.6.1.2.1.25.2.3.1.4.63"
    DISK_USAGE_LINUX = "iso.3.6.1.2.1.25.2.3.1.6.63"

    TOTAL_PROCESSES = "1.3.6.1.2.1.25.1.6"
    # snmpwalk -t 10 -v 2c -c evil localhost OID


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
    agent_agent_sys_type: str = ""
    agent_uptime: int = 0
    INTERFACES_NUMBER: int = 0
    INTERFACES: list[InterfaceData] = []
    agent_cpu_usage: int = 0
    agent_ram_total: int = 0
    agent_ram_usage: int = 0
    agent_ram_usage_percent: int = 0
    agent_ram_bytes_per_unit: int = 0
    agent_disk_total: int = 0
    agent_disk_usage: int = 0
    agent_disk_usage_percent: int = 0
    agent_disk_bytes_per_unit: int = 0
    agent_tcp_packages: int = 0
    configured_tcp_packages: int = 10
    exceded_recently: bool = False

    def check_tcp_counter(self):
        if self.agent_tcp_packages >= self.configured_tcp_packages:
            keys = [a for a in dir(self) if not a.startswith('__')]
            key_values = vars(self)
            template_str: str = ""
            with open("reportTemplate.html", "r") as template:
                template_str = template.read()
            for k in keys:
                if k in key_values and type(key_values[k])!=type([]):
                    template_str = template_str.replace(k, str(key_values[k]))
            if not self.exceded_recently:
                pdfkit.from_string(template_str, f'{uuid.uuid4()}.pdf')
                self.exceded_recently = True

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
            "agent_agent_sys": self.agent_agent_sys_type,
            "agent_uptime": self.agent_uptime,
            "INTERFACES_NUMBER": self.INTERFACES_NUMBER,
            "INTERFACES": self.INTERFACES,
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
            "agent_agent_sys": self.agent_agent_sys_type,
            "agent_uptime": self.agent_uptime,
            "INTERFACES_NUMBER": self.INTERFACES_NUMBER,
            "INTERFACES": [interface.to_json() for interface in self.INTERFACES]
        }

    def __str__(self):
        str_representation = f"Agent ID: {self.agent_id} \n" \
                             f"Agent IP Address: {self.agent_ip_address}\n" \
                             f"Agent IP Address: {self.agent_ip_address}\n" \
                             f"Agent System: {self.agent_agent_sys_type}\n" \
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

    def snmp_query(self, community_name, host, oid, split: bool = True):
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
                result = var_b.split()[2] if split else var_b
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
        agent.agent_agent_sys_type = self.snmp_query(agent.community_name, agent.agent_ip_address,
                                                     SNMPObjectId.SYS_TYPE,split=False)
        is_windows = "Windows" in agent.agent_agent_sys_type
        is_linux = "Linux" in agent.agent_agent_sys_type
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
        oid_cpu = ""
        oid_total_disk = ""
        oid_total_ram = ""
        oid_used_disk = ""
        oid_used_ram = ""
        if is_windows:
            print("winbus detected")
            oid_cpu = SNMPObjectId.PROCESSOR_USAGE_WINBUS
            oid_total_disk = SNMPObjectId.TOTAL_DISK_WINDOWS
            oid_total_ram = SNMPObjectId.TOTAL_RAM_MEMORY_WINBUS
            oid_used_disk = SNMPObjectId.DISK_USAGE_WINDOWS
            oid_used_ram = SNMPObjectId.USED_RAM_MEMORY_WINBUS
        if is_linux:
            print("real os detected")
            oid_cpu = SNMPObjectId.PROCESSOR_USAGE_LINUX
            oid_total_disk = SNMPObjectId.TOTAL_DISK_LINUX
            oid_total_ram = SNMPObjectId.TOTAL_RAM_MEMORY_LINUX
            oid_used_disk = SNMPObjectId.DISK_USAGE_LINUX
            oid_used_ram = SNMPObjectId.USED_RAM_MEMORY_LINUX

        agent.agent_cpu_usage = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, oid_cpu))
        agent.agent_ram_total = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, oid_total_ram))
        agent.agent_ram_usage = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, oid_used_ram))
        # agent.agent_ram_usage_percent = agent.agent_ram_usage / (agent.agent_ram_usage_percent / 100)
        agent.agent_disk_total = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, oid_total_disk))
        agent.agent_disk_usage = int(
            self.snmp_query(agent.community_name, agent.agent_ip_address, oid_used_disk))
        agent.agent_disk_usage_percent = agent.agent_disk_usage / (agent.agent_disk_total / 100)
        rrd_value = f"N:{input_unicast_traffic}:{input_ip_traffic}:{output_icmp_echos}:{input_tcp_segments}:{input_udp_segments}:{agent.agent_cpu_usage}:{agent.agent_ram_usage_percent}:{agent.agent_disk_usage_percent}"
        agent.agent_tcp_packages = input_tcp_segments
        rrdtool.update(agent.rdd_file, rrd_value)
        agent.check_tcp_counter()
        # rrdtool.dump(agent.rdd_file, f"{agent.rdd_file.split('.')[0]}.xml")
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
                             "DS:cpuusage:GAUGE:600:U:U",
                             "DS:cpuram:GAUGE:600:U:U",
                             "DS:cpudisk:GAUGE:600:U:U",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5",
                             "RRA:AVERAGE:0.5:6:5")
        if ret:
            print(rrdtool.error())
    except Exception as e:
        print(">> ERROR AT RDD FILE CREATION:", e)


def calculate_trend(agent_file_name: str):
    ultima_lectura = int(rrdtool.last(agent_file_name))
    tiempo_final = ultima_lectura
    tiempo_inicial = tiempo_final - 2000
    just_name = agent_file_name.split('.')[0]
    ret = rrdtool.graph(f"trend_{just_name}.png",
                        "--start", str(tiempo_inicial),
                        "--end", str(tiempo_final),
                        "--vertical-label=Carga CPU",
                        "--title=Tendencia del uso del CPU",
                        "--color", "ARROW#009900",
                        '--vertical-label', "Uso de CPU (%)",
                        '--lower-limit', '0',
                        '--upper-limit', '100',
                        f"DEF:carga={agent_file_name}:CPUload:AVERAGE",
                        "AREA:carga#00FF00:Carga CPU",
                        "LINE1:30",
                        "AREA:5#ff000022:stack",
                        "VDEF:CPUlast=carga,LAST",
                        "VDEF:CPUmin=carga,MINIMUM",
                        "VDEF:CPUavg=carga,AVERAGE",
                        "VDEF:CPUmax=carga,MAXIMUM",
                        "COMMENT:Now          Min             Avg             Max",
                        "GPRINT:CPUlast:%12.0lf%s",
                        "GPRINT:CPUmin:%10.0lf%s",
                        "GPRINT:CPUavg:%13.0lf%s",
                        "GPRINT:CPUmax:%13.0lf%s",
                        "VDEF:m=carga,LSLSLOPE",
                        "VDEF:b=carga,LSLINT",
                        'CDEF:tendencia=carga,POP,m,COUNT,*,b,+',
                        "LINE2:tendencia#FFBB00")


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
                json_data = {
                    "filename": filename,
                    "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
                    "data": [agent.to_json() for agent in self.AGENTS]
                }

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
