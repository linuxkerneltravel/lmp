from influxdb import InfluxDBClient
from socket import AF_INET, AF_INET6, inet_ntop
from struct import pack


############## pre defines #################
client = None

def create_client():
    global client
    if client is None:
        client = InfluxDBClient('localhost', 8086, 'root', 'root', 'network_subsystem')
        client.create_database('network_subsystem')


################## nic_throughput ###################
def export_nic_throughput(NICName, QueueID, avg_size, BPS, PPS, measurement):
    create_client()
    json_body = [
        {
            "measurement": measurement,
            "tags": {
                "NICName": NICName,
                "QueueID": QueueID
            },
            "fields": {
                "avg_size": float(avg_size),
                "BPS": float(BPS),
                "PPS": float(PPS)
            }
        }
    ]
    client.write_points(json_body)


################## tcp_connection ###################
def export_tcp_connection(data, ip):
    create_client()
    direction = "accept" if data.direction==0 else "connect"
    if ip==4:
        daddr = inet_ntop(AF_INET, pack("I", data.daddr)).encode()
        saddr = inet_ntop(AF_INET, pack("I", data.saddr)).encode()
    else:
        daddr = inet_ntop(AF_INET6, data.daddr).encode()
        saddr = inet_ntop(AF_INET6, data.saddr).encode()
    json_body = [
        {
            "measurement": "tcp_connection",
            "fields": {
                "PID": data.pid,
                "TASK": data.task,
                "IP": data.ip,
                "DADDR": daddr,
                "DPORT": data.dport,
                "SADDR": saddr,
                "SPORT": data.sport,
                "DIRECTION": direction
            }
        }
    ]
    client.write_points(json_body)


################## tcp_bytes ###################
def export_tcp_bytes(data, send_bytes, recv_bytes):
    create_client()
    json_body = [
        {
            "measurement": "tcp_bytes",
            "tags": {
                "PID": data.pid,
                "TASK": data.task,
                "SADDR": data.saddr,
                "SPORT": data.sport,
                "DADDR": data.daddr,
                "DPORT": data.dport,
            },
            "fields": {
                "RX_KB": int(recv_bytes/1024),
                "TX_KB": int(send_bytes/1024),
            }
        }
    ]
    client.write_points(json_body)


################## tcp_inerrs ###################
def export_tcp_inerrs(data, ip, reason, state):
    create_client()
    if ip==4:
        daddr = inet_ntop(AF_INET, pack("I", data.daddr)).encode()
        saddr = inet_ntop(AF_INET, pack("I", data.saddr)).encode()
    else:
        daddr = inet_ntop(AF_INET6, data.daddr).encode()
        saddr = inet_ntop(AF_INET6, data.saddr).encode()
    json_body = [
        {
            "measurement": "tcp_inerrs",
            "fields": {
                "PID": data.pid,
                "TASK": data.task,
                "IP": data.ip,
                "DADDR": daddr,
                "DPORT": data.dport,
                "SADDR": saddr,
                "SPORT": data.sport,
                "REASON": reason,
                "STATE": state
            }
        }
    ]
    client.write_points(json_body)


################## delay_analysis_in ###################
def export_delay_analysis_in(data):
    create_client()
    daddr = inet_ntop(AF_INET, pack("I", data.daddr)).encode()
    saddr = inet_ntop(AF_INET, pack("I", data.saddr)).encode()
    json_body = [
        {
            "measurement": "delay_analysis_in",
            "fields": {
                "SADDR": saddr,
                "SPORT": data.sport,
                "DADDR": daddr,
                "DPORT": data.dport,
                "SEQ": data.seq,
                "ACK": data.ack,
                "TIME_TOTAL": int(data.total_time/1000),
                "TIME_MAC": int(data.mac_time/1000),
                "TIME_IP": int(data.ip_time/1000),
                "TIME_TCP": int(data.tcp_time/1000),
            }
        }
    ]
    client.write_points(json_body)


################## delay_analysis_in_v6 ###################
def export_delay_analysis_in_v6(data):
    create_client()
    daddr = inet_ntop(AF_INET6, data.daddr).encode()
    saddr = inet_ntop(AF_INET6, data.saddr).encode()
    json_body = [
        {
            "measurement": "delay_analysis_in_v6",
            "fields": {
                "SADDR": saddr,
                "SPORT": data.sport,
                "DADDR": daddr,
                "DPORT": data.dport,
                "SEQ": data.seq,
                "ACK": data.ack,
                "TIME_TOTAL": int(data.total_time/1000),
                "TIME_MAC": int(data.mac_time/1000),
                "TIME_IP": int(data.ip_time/1000),
                "TIME_TCP": int(data.tcp_time/1000),
            }
        }
    ]
    client.write_points(json_body)


################## delay_analysis_out ###################
def export_delay_analysis_out(data):
    create_client()
    daddr = inet_ntop(AF_INET, pack("I", data.daddr)).encode()
    saddr = inet_ntop(AF_INET, pack("I", data.saddr)).encode()
    json_body = [
        {
            "measurement": "delay_analysis_out",
            "fields": {
                "SADDR": saddr,
                "SPORT": data.sport,
                "DADDR": daddr,
                "DPORT": data.dport,
                "SEQ": data.seq,
                "ACK": data.ack,
                "TIME_TOTAL": int(data.total_time/1000),
                "TIME_QDisc": int(data.qdisc_time/1000),
                "TIME_IP": int(data.ip_time/1000),
                "TIME_TCP": int(data.tcp_time/1000),
            }
        }
    ]
    client.write_points(json_body)


################## delay_analysis_out_v6 ###################
def export_delay_analysis_out_v6(data):
    create_client()
    daddr = inet_ntop(AF_INET6, data.daddr).encode()
    saddr = inet_ntop(AF_INET6, data.saddr).encode()
    json_body = [
        {
            "measurement": "delay_analysis_out_v6",
            "fields": {
                "SADDR": saddr,
                "SPORT": data.sport,
                "DADDR": daddr,
                "DPORT": data.dport,
                "SEQ": data.seq,
                "ACK": data.ack,
                "TIME_TOTAL": int(data.total_time/1000),
                "TIME_QDisc": int(data.qdisc_time/1000),
                "TIME_IP": int(data.ip_time/1000),
                "TIME_TCP": int(data.tcp_time/1000),
            }
        }
    ]
    client.write_points(json_body)


################## tcp_flow ###################
def export_tcp_flow(data, ip, state, flag):
    create_client()
    if ip==4:
        daddr = inet_ntop(AF_INET, pack("I", data.daddr)).encode()
        saddr = inet_ntop(AF_INET, pack("I", data.saddr)).encode()
    else:
        daddr = inet_ntop(AF_INET6, data.daddr).encode()
        saddr = inet_ntop(AF_INET6, data.saddr).encode()
    json_body = [
        {
            "measurement": "tcp_flow",
            "fields": {
                "SADDR": saddr,
                "SPORT": data.sport,
                "DADDR": daddr,
                "DPORT": data.dport,
                "SEQ": data.seq,
                "ACK": data.ack,
                "RTT(us)": data.srtt >> 3,
                "STATE": state,
                "TCPFLAGS": flag,
                "SND_CWnd": data.snd_cwnd,
                "RCV_CWnd": data.rcv_wnd,
                "DURATION": data.duration
            }
        }
    ]
    client.write_points(json_body)

