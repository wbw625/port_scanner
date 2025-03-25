import socket
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import nmap
import requests
from get_ip import get_ip

common_ports = [21, 22, 80, 81, 135, 139, 443, 445, 1433, 1521, 3306, 5432, 6379, 7001, 8000, 8080, 8089, 9000, 9200, 11211, 27017]


def get_service_name(port):
    """尝试从系统数据库获取端口的服务名称"""
    try:
        return socket.getservbyport(port)
    except (OSError, socket.error):
        return None

def get_iana_service_name(port):
    """从 IANA 端口注册表查询端口信息"""
    url = f"https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search={port}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            # 解析 HTML 页面（这里简单判断是否包含端口信息）
            if f"Port {port}" in response.text:
                return f"详细信息请访问: {url}"
        return None
    except requests.RequestException:
        return None

def scan_port_with_nmap(host, port):
    """使用 nmap 获取端口的详细信息"""
    nm = nmap.PortScanner()
    # service_info = {}

    nm.scan(ip, str(port), '-sV')

    for host in nm.all_hosts():
        lport = nm[host]['tcp'].keys()
        for port in lport:
            if nm[host]['tcp'][port]['state'] == 'open':
                service = nm[host]['tcp'][port]['name']
                additional_info = nm[host]['tcp'][port].get('extrainfo')

                # 如果服务是 http/https，尝试获取 HTTP 头信息
                if service in ['http', 'https']:
                    url = f"{service}://{host}:{port}"
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                    }
                    try:
                        response = requests.get(url, headers=headers, timeout=3)
                        additional_info = f"HTTP/{response.raw.version / 10} {response.status_code} {response.reason}"
                    except requests.RequestException:
                        additional_info = "无法获取 HTTP 详细信息"

    return service, additional_info

def scan_port(host, port):
    """扫描单个端口"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((host, port))
    if result == 0:
        # 获取端口服务名称和额外信息
        service = None
        additional_info = None
        if not service:
            service, additional_info = scan_port_with_nmap(host, port)
            if not service:
                service = get_service_name(port)
                if not service:
                    iana_info = get_iana_service_name(port)
                    if iana_info:
                        service = iana_info
                    else:
                        service = "未知"
        return port, service, additional_info
    sock.close()
    return None

def scan_ports(host, start_port=1, end_port=1024, max_threads=100):
    """多线程扫描端口"""
    open_ports = []
    total_ports = end_port - start_port + 1
    scanned_ports = 0

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, host, port): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            scanned_ports += 1
            port = futures[future]
            progress = (scanned_ports / total_ports) * 100
            print(f"\r--正在扫描端口 {port}... 进度: {progress:.2f}%", end="")

            result = future.result()
            if result:
                port, service, additional_info = result
                open_ports.append((port, service, additional_info))
                print(f"\n----端口 {port} 已打开服务 - {service}")

    print("\n扫描完成。")
    return open_ports

def save_to_file(open_ports, filename="port_scan_results.txt"):
    """保存扫描结果到文件"""
    with open(filename, "a") as file:
        for port, service in open_ports:
            file.write(f"--端口 {port} 已打开 - {service}\n")

def display_results(open_ports):
    """显示扫描结果并解释端口作用"""
    if not open_ports:
        print("未找到打开的端口。")
        return

    print(f"\n对 {ip} 的扫描结果：")
    print("-" * 50)
    for port, service, additional_info in open_ports:
        if service == "未知":
            print(f"端口 {port}: 未知（此端口可能用于自定义或不常见的服务，建议进一步调查。）")
        else:
            if additional_info == None or additional_info == "":
                print(f"端口 {port}: {service}")
            else:
                print(f"端口 {port}: {service}, {additional_info}")

    print("-" * 50)

if __name__ == "__main__":
    # 使用 argparse 解析命令行参数
    parser = argparse.ArgumentParser(description="扫描指定主机的端口。")
    parser.add_argument("host", help="要扫描的主机（例如：www.163.com）")
    parser.add_argument("-s", "--start-port", type=int, default=1, help="起始端口（默认：1）")
    parser.add_argument("-e", "--end-port", type=int, default=1024, help="结束端口（默认：1024）")
    parser.add_argument("-t", "--threads", type=int, default=10, help="最大线程数（默认：100）")
    args = parser.parse_args()

    host = args.host
    start_port = args.start_port
    end_port = args.end_port
    max_threads = args.threads

    print(f"正在扫描 {host} 的端口范围 {start_port} 到 {end_port}，使用 {max_threads} 个线程...")
    ip = get_ip(host)
    print(f"IP 地址: {ip}")
    if not ip:
        sys.exit(1)
    open_ports = scan_ports(ip, start_port, end_port, max_threads)
    display_results(open_ports)