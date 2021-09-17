from pysnmp.hlapi import *
import rrdtool
import uuid
import shlex
import sqlite3
import sys
from sqlite3 import Error


class SNMPUtils:
    def snmp_query(comunidad, host, oid):
        error_indication, error_status, error_index, var_binds = next(
            getCmd(SnmpEngine(),
                   CommunityData(comunidad),
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


class InterfaceData:
    STATUS: str = ""
    DESCRIPTION: str = ""

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
    agent_version: str = ""
    agent_os_logo: str = ""
    agent_location: str = ""
    agent_ports_number: str = ""
    agent_uptime = None
    INTERFACES_NUMBER: int = 0
    INTERFACES: list[InterfaceData] = []

    def __init__(self, address: str, port: int, snmp_version: int, community_name: str, agent_file_name: str,
                 agent_id: int = 0):
        self.agent_ip_address = address
        self.port = port
        self.snmp_version = snmp_version
        self.community_name = community_name
        self.rdd_file = agent_file_name
        self.agent_id = agent_id


def create_rdd_file(agent_file_name):
    ret = rrdtool.create(agent_file_name,
                         "--start", 'N',
                         "--step", '60',
                         "DS:inoctets:COUNTER:600:U:U",
                         "DS:outoctets:COUNTER:600:U:U",
                         "RRA:AVERAGE:0.5:6:5",
                         "RRA:AVERAGE:0.5:1:20")
    if ret:
        print(rrdtool.error())


class SNMPMonitor:
    AGENTS: list[SNMPAgent] = []
    _sqlite_con = None
    _sqlite_cursor = None

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
        print((
            agent.agent_ip_address,
            agent.rdd_file,
            agent.port,
            agent.snmp_version,
            agent.community_name, 1))
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

    def remove_agent(self, agent_id: int):
        agent = next((agent for agent in self.AGENTS if agent.agent_id == agent_id))
        if agent:
            self._delete_sqlite_agent(agent)
            self.AGENTS.remove(agent)

        return "success"

    def close(self):
        self._sqlite_con.close()

    def __init__(self):
        try:
            self._init_db()
            self._load_sqlite_agents()

        except Error as e:
            print(e)
            print("Expurosion! ", sys.exc_info()[0])
