from pysnmp.hlapi import *
import rrdtool
import uuid
import shlex


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

    def __init__(self, direction: str, port: int, snmp_version: int, community_name: str, agent_file_name: str):
        self.agent_ip_address = direction
        self.port = port
        self.snmp_version = snmp_version
        self.community_name = community_name
        self.rdd_file = agent_file_name


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

    # AGENTS TEMPLATE:
    # {"STATUS":0, "INTERFACES_NUMBER":0,"INTERFACES":[{"STATUS":"","DESCRIPTION":""}]}\
    def add_agent(self, direction, port, snmp_version, community_name):
        agent_file_name = f"{direction}_{port}_SNMP{snmp_version}_{community_name}_{uuid.uuid4()}.rdd"
        create_rdd_file(agent_file_name)
        agent = SNMPAgent(direction, port, snmp_version, community_name, agent_file_name)
        self.AGENTS.append(agent)
        return agent

    def remove_device(self, agent_index: int):
        self.AGENTS.remove(self.AGENTS[agent_index])
        return "success"
