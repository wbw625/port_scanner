import ipaddress
import socket
import re

def is_ip(input_str):
    try:
        ipaddress.ip_address(input_str)
        return True
    except ValueError:
        return False
    
def is_domain(input_str):
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.fullmatch(domain_pattern, input_str) is not None


def domain_to_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_ip(input_str):
    if is_ip(input_str):
        ip = input_str
        return ip
    else:
        if input_str.startswith("http://") or input_str.startswith("https://"):
            input_str = input_str.split("://")[1]
        if is_domain(input_str):
            ip = domain_to_ip(input_str)
            return ip
    print("无效的 IP 地址或域名。")
    ip = None
    return ip

if __name__ == "__main__":
    input_str = input("请输入 IP 地址或域名: ")
    ip = get_ip(input_str)
    print(f"IP 地址: {ip}")