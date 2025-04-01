from get_ip import get_ip
import socket
from scapy.all import IP, TCP, sr1, sr, send, sendp

common_ports = [21, 22, 80, 81, 135, 139, 443, 445, 1433, 1521, 3306, 5432, 6379, 7001, 8000, 8080, 8089, 9000, 9200, 11211, 27017]

def open_ports_method1(ip):
    open_ports = []
    for port in common_ports:
        print(f"Checking port {port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port} is open.")
            open_ports.append(port)
        else:
            print(f"Port {port} is closed.")
        sock.close()
    return open_ports


def open_ports_method2(ip):
    open_ports = []
    for port in common_ports:
        # 构造SYN包
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response is not None and TCP in response:
            if response[TCP].flags == 0x12:  # 如果收到SYN-ACK
                # 发送RST包复位连接
                send_rst = sr(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                open_ports.append(port)
                print(f"Port {port} is open.")
            elif response[TCP].flags == 0x14:  # 如果收到RST
                print(f"Port {port} is closed.")
        else:
            print(f"Port {port} is closed.")
    return open_ports


def get_ports(input_str):
    ip = get_ip(input_str)
    if ip is None:
        print("Invalid IP address or domain.")
        return []
    else:
        print(f"IP: {ip}")
    open_ports = open_ports_method1(ip) + open_ports_method2(ip)
    return open_ports

if __name__ == "__main__":
    input_str = input("Please enter IP or domain: ")
    open_ports = get_ports(input_str)
    print(f"Open ports: {open_ports}")