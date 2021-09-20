from datetime import date
from SnmpAgentMonitor import SNMPMonitor


def calculate_live_days():
    birthdate = date(day=23, month=11, year=1997)
    check_date = date(day=10, month=9, year=2021)
    diff = check_date - birthdate
    return diff.days % 3


print(f'>> B l o q u e:  {calculate_live_days()}')
# 1) Paquetes unicast que ha recibido una interfaz
# 1) Paquetes recibidos a protocolos IPv4, incluyendo los que tienen errores.
# 1) Mensajes ICMP echo que ha enviado el agente
# 1) Segmentos recibidos, incluyendo los que se han recibido con errores.
# 1) Datagramas entregados a usuarios UDP
monitor = SNMPMonitor()
menu_options = [" 1) ADD AN AGENT", " 2) REMOVE AGENT", " 3) LIST AGENTS", " 4) EXPORT CURRENT AGENTS DATA", " 0) EXIT", ""]


def evaluate_op(cop: int):
    exit_monitor = False
    try:
        if cop == 0:
            monitor.close()
            exit_monitor = True
            print("< S E E ~ Y O U ~ S P A C E ~ C O W B O Y />")
        elif cop == 1:
            print("PLEASE INSERT AGENT DATA WITH THE FOLLOWING FORMAT")
            print("IP PORT SNMP_VERSION COMMUNITY_NAME")
            print("EXAMPLE:")
            print("192.168.0.234 8080 3 community")
            print("")
            input_data = str(input()).split(' ')
            print(input_data)
            monitor.add_agent(input_data[0], input_data[1], input_data[2], input_data[3])
        elif cop == 2:
            print("TYPE THE ID OF AGENT")
            for agent in monitor.AGENTS:
                print(
                    f">> ID: {agent.agent_id} <<- {agent.agent_ip_address}:{agent.port} SNMP-V{agent.snmp_version} ({agent.community_name})")
            monitor.remove_agent(int(input()))
        elif cop == 3:
            for agent in monitor.AGENTS:
                print(
                    f">> ID: {agent.agent_id} <<- {agent.agent_ip_address}:{agent.port} SNMP-V{agent.snmp_version} ({agent.community_name})")
            if len(monitor.AGENTS) == 0:
                print("> > 0  AGENTS < <")
            print("TYPE ENTER TO CONTINUE")
            input()
        elif cop == 4:
            file_name = monitor.export_current_data()
            print(f"SESSION DATA DUMPED AS {file_name}")
    except:
        print(" > > E R R O R < <")
    return exit_monitor


while True:
    print("> > S N M P ~ M O N I T O R < <")
    print("SELECT THE NUMBER OF DESIRED OPTION FROM THE MENU")
    for op in menu_options:
        print(op)
    try:
        if evaluate_op(int(input())):
            break
    except:
        print(" > > E R R O R < < ")
        print(" > > SELECT A VALID OPTION >:P < < ")
