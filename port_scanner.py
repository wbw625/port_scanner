import socket
import ssl
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from get_ports import get_ports
import requests
from get_ip import get_ip

common_ports = [21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 443, 445, 1433, 1521, 3306, 5432, 6379, 7001, 8000, 8080, 8089, 9000, 9200, 11211, 27017]

common_services = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Hypertext Transfer Protocol)",
    110: "POP3 (Post Office Protocol)",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (HTTP Secure)",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

def socket_get_banner(host, port):
    """获取指定端口的 Banner 信息"""
    try:
        # 创建 socket 连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        # 连接到目标主机和端口
        sock.connect((host, port))

        # 接收数据
        banner = sock.recv(1024).decode('utf-8', errors='ignore')

        # 关闭连接
        sock.close()

        return banner.strip()

    except Exception as e:
        return f"错误: {str(e)}"

def scan_service_banner(ip: str, port: int) -> dict[int, str]:
    """扫描指定 IP 地址的端口并返回结果"""
    service_banner = socket_get_banner(ip, port)
    if service_banner:
        if service_banner.startswith("SSH-"):
            service = "SSH"
        elif service_banner.startswith("220"):
            service = "SMTP"
        else:
            service = "未知"

        print(f"端口 {port} ({service}): {service_banner}")
    return (service, service_banner)


def get_http_header(host, port):
    """发送 HTTP 请求并返回响应头"""
    try:
        # 创建一个 socket 连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(20)

        # 使用 SSL/TLS 包装 socket
        context = ssl.create_default_context()
        context.check_hostname = False  # 禁用主机名检查
        context.verify_mode = ssl.CERT_NONE  # 禁用证书验证
        sock = context.wrap_socket(sock, server_hostname=host)
        
        # 连接到目标主机和端口
        sock.connect((host, port))

        # 构造 HTTPS 请求
        request = (
            "GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
            "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
            "Accept-Encoding: gzip, deflate, br\r\n"  # 允许压缩响应
            "Connection: close\r\n\r\n"
        )

        # 接收响应
        response = b""
        while True:
            data = sock.recv(1024)
            if not data:
                break
            response += data

        # 关闭连接
        sock.close()

        # 解码响应并获取头部信息
        response = response.decode('utf-8', errors='ignore')
        headers = response.split("\r\n\r\n")[0]  # 获取 HTTP 头部部分
        
        return ("HTTPS", headers)

    except Exception as e:
        return f"未知", str(e)

def scan_port(host, port, original_host):
    """扫描单个端口"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((host, port))

    if result == 0:
        # 获取端口服务名称和额外信息
        service = None
        additional_info = None
        if not service:
            service, additional_info = scan_service_banner(host, port)
            if service == "未知" or additional_info == "" or additional_info == None:
                # 尝试使用 HTTPS 请求获取更多信息
                service, additional_info = get_http_header(host, port)
                if not service:
                    service = "未知"
            
        return port, service, additional_info
    sock.close()
    return None

def scan_ports(host, original_host, start_port=1, end_port=1024, max_threads=100):
    """多线程扫描端口"""
    open_ports = []
    get_open_ports = get_ports(host)
    total_ports = len(get_open_ports)
    scanned_ports = 0

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, original_host): port
            for port in get_open_ports
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

def display_results(open_ports):
    """显示扫描结果并解释端口作用"""
    if not open_ports:
        print("未找到打开的端口。")
        return

    print(f"\n对 {ip} 的扫描结果：")
    print("-" * 50)
    for port, service, additional_info in open_ports:
        if service == "未知":
            print(f"--端口 {port}: 未知（此端口可能用于自定义或不常见的服务，建议进一步调查。）")
        else:
            if additional_info == None or additional_info == "":
                print(f"--端口 {port}: {service}")
            else:
                print(f"--端口 {port}: {service} \n----额外信息:\n{additional_info}")

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
    open_ports = scan_ports(ip, host, start_port, end_port, max_threads)
    display_results(open_ports)



def service_scan_http(ip: str, ports: list[int]) -> list[dict[str, int | str]]:
    return [
        {"port": 80, "banner": "HTTP/1.1 200 OK", "protocol": "HTTP"},
        {"port": 8080, "banner": "HTTP/1.1 200 OK", "protocol": "HTTP"},
    ]


def service_scan_https(ip: str, ports: list[int]) -> list[dict[str, int | str]]:
    return [{"port": 443, "banner": "HTTP/1.1 200 OK", "protocol": "HTTPS"}]


def service_scan_ssh(ip: str, ports: list[int]) -> list[dict[str, int | str]]:
    return [{"port": 22, "banner": "SSH-2.0-OpenSSH_7.9", "protocol": "SSH"}]


def service_scan(ip: str, ports: list[int]) -> list[dict[str, int | str]]:
    raise Exception("Not implemented")
    return list(
        service_scan_http(ip, ports)
        + service_scan_https(ip, ports)
        + service_scan_ssh(ip, ports)
    )