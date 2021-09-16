from datetime import date


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
