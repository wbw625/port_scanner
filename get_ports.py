from get_ip import get_ip
import socket

common_ports = [21, 22, 80, 81, 135, 139, 443, 445, 1433, 1521, 3306, 5432, 6379, 7001, 8000, 8080, 8089, 9000, 9200, 11211, 27017]

def get_ports(input_str):
    ip = get_ip(input_str)
    if ip is None:
        print("Invalid IP address or domain.")
        return []
    else:
        print(f"IP: {ip}")
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

if __name__ == "__main__":
    input_str = input("Please enter IP or domain: ")
    open_ports = get_ports(input_str)
    print(f"Open ports: {open_ports}")