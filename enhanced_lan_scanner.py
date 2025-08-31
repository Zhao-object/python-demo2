import os
import sys
import time
import json
import csv
import socket
import struct
import subprocess
import threading
import ipaddress
import platform
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import nmap
import netifaces
import requests
import logging
from prettytable import PrettyTable

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('lan_scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 缓存目录设置
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".lan_scanner_cache")
os.makedirs(CACHE_DIR, exist_ok=True)

# MAC地址厂商数据库缓存文件
MAC_VENDOR_CACHE = os.path.join(CACHE_DIR, "mac_vendors.json")

# 最大线程数（根据CPU核心数动态调整）
MAX_WORKERS = min(100, os.cpu_count() * 10)


class AdvancedLANScanner:
    def __init__(self, args):
        self.args = args
        self.arp_table = {}
        self.scan_results = {}
        self.network_interfaces = self.get_network_interfaces()
        self.mac_vendors = self.load_mac_vendor_cache()
        self.nm = nmap.PortScanner() if self.check_nmap_installed() else None
        self.lock = threading.Lock()

    def check_nmap_installed(self):
        """检查nmap是否安装"""
        try:
            subprocess.run(['nmap', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("未检测到nmap，部分高级功能将不可用。请安装nmap以获得完整功能。")
            return False

    def load_mac_vendor_cache(self):
        """加载MAC地址厂商缓存"""
        try:
            if os.path.exists(MAC_VENDOR_CACHE):
                with open(MAC_VENDOR_CACHE, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.warning(f"加载MAC厂商缓存失败: {e}")
            return {}

    def save_mac_vendor_cache(self):
        """保存MAC地址厂商缓存"""
        try:
            with open(MAC_VENDOR_CACHE, 'w') as f:
                json.dump(self.mac_vendors, f)
        except Exception as e:
            logger.warning(f"保存MAC厂商缓存失败: {e}")

    def get_network_interfaces(self):
        """获取所有有效网络接口信息"""
        interfaces = []
        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET not in addrs:
                    continue

                ipv4_info = addrs[netifaces.AF_INET][0]
                ip_address = ipv4_info['addr']
                netmask = ipv4_info['netmask']

                # 跳过本地回环和无效IP
                if ip_address.startswith('127.') or ip_address.startswith('169.254.'):
                    continue

                # 获取网关
                gateway = None
                if netifaces.AF_INET in netifaces.gateways():
                    default_gw = netifaces.gateways()[netifaces.AF_INET][0]
                    gateway = default_gw[0] if default_gw else None

                # 计算网络地址和网段
                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
                cidr = str(network)

                interfaces.append({
                    'name': iface,
                    'ip_address': ip_address,
                    'netmask': netmask,
                    'gateway': gateway,
                    'cidr': cidr,
                    'network': str(network.network_address),
                    'broadcast': str(network.broadcast_address)
                })
            except Exception as e:
                logger.debug(f"获取接口 {iface} 信息失败: {e}")
                continue

        return interfaces

    def select_interface(self):
        """让用户选择要扫描的网络接口"""
        if not self.network_interfaces:
            logger.error("未检测到有效网络接口")
            return None

        if len(self.network_interfaces) == 1:
            return self.network_interfaces[0]

        print("\n检测到以下网络接口:")
        for i, iface in enumerate(self.network_interfaces, 1):
            print(f"{i}. {iface['name']} - IP: {iface['ip_address']} - 网段: {iface['cidr']}")

        while True:
            try:
                choice = int(input("请选择要扫描的接口 (1-{}): ".format(len(self.network_interfaces))))
                if 1 <= choice <= len(self.network_interfaces):
                    return self.network_interfaces[choice - 1]
                print("无效选择，请重试")
            except ValueError:
                print("请输入数字")

    def is_admin(self):
        """检查是否以管理员权限运行"""
        try:
            return os.geteuid() == 0
        except AttributeError:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    def update_arp_table(self):
        """更新ARP表信息"""
        try:
            system = platform.system()
            arp_output = ""

            if system == "Windows":
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                arp_output = result.stdout
            elif system in ["Linux", "Darwin"]:  # Linux 和 macOS
                result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
                arp_output = result.stdout
            else:
                logger.warning(f"不支持的操作系统: {system}")
                return

            # 解析ARP表
            new_arp_table = {}
            lines = arp_output.split('\n')

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Windows格式: IPv4 地址         物理地址              类型
                # Linux/macOS格式: ? (192.168.1.1) at xx:xx:xx:xx:xx:xx [ether] on eth0
                if system == "Windows":
                    parts = line.split()
                    if len(parts) >= 2 and self.is_valid_ip(parts[0]) and self.is_valid_mac(parts[1]):
                        ip = parts[0]
                        mac = parts[1].upper()
                        new_arp_table[ip] = mac
                else:
                    if 'at' in line and 'on' in line:
                        ip_part = line.split('(')[1].split(')')[0] if '(' in line and ')' in line else None
                        mac_part = line.split('at')[1].split()[0] if 'at' in line else None

                        if ip_part and mac_part and self.is_valid_ip(ip_part) and self.is_valid_mac(mac_part):
                            ip = ip_part
                            mac = mac_part.upper()
                            new_arp_table[ip] = mac

            self.arp_table = new_arp_table
            logger.info(f"已更新ARP表，包含 {len(new_arp_table)} 条记录")

        except Exception as e:
            logger.error(f"更新ARP表失败: {e}")

    def is_valid_ip(self, ip):
        """验证IP地址有效性"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False

    def is_valid_mac(self, mac):
        """验证MAC地址有效性"""
        mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        import re
        return re.match(mac_pattern, mac) is not None

    def ping_ip(self, ip, count=2, timeout=1):
        """Ping指定IP地址"""
        try:
            system = platform.system()
            params = []

            if system == "Windows":
                params = ['ping', '-n', str(count), '-w', str(timeout * 1000), ip]
            else:
                params = ['ping', '-c', str(count), '-W', str(timeout), ip]

            result = subprocess.run(
                params,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # 检查是否可达
            is_alive = result.returncode == 0

            # 提取响应时间
            avg_rtt = None
            output = result.stdout

            if is_alive:
                if system == "Windows":
                    # Windows格式: 平均 = 3ms
                    for line in output.split('\n'):
                        if '平均' in line and '=' in line:
                            parts = line.split('=')
                            if len(parts) >= 3:
                                avg_rtt = float(parts[2].strip().split()[0])
                                break
                else:
                    # Linux/macOS格式: rtt min/avg/max/mdev = 1.234/2.345/3.456/0.123 ms
                    for line in output.split('\n'):
                        if 'rtt' in line and '/' in line:
                            parts = line.split('/')
                            if len(parts) >= 5:
                                avg_rtt = float(parts[1])
                                break

            return {
                'ip': ip,
                'alive': is_alive,
                'avg_rtt': avg_rtt
            }

        except Exception as e:
            logger.debug(f"Ping {ip} 失败: {e}")
            return {'ip': ip, 'alive': False, 'avg_rtt': None}

    def get_mac_vendor(self, mac):
        """通过MAC地址获取厂商信息"""
        if not mac:
            return "未知"

        # 标准化MAC地址
        mac_prefix = mac[:8].upper().replace('-', ':')

        # 检查缓存
        if mac_prefix in self.mac_vendors:
            return self.mac_vendors[mac_prefix]

        # 尝试从API获取
        try:
            response = requests.get(f"https://api.macvendors.com/{mac_prefix}", timeout=5)
            if response.status_code == 200:
                vendor = response.text.strip()
                self.mac_vendors[mac_prefix] = vendor
                return vendor
        except Exception as e:
            logger.debug(f"获取MAC厂商信息失败: {e}")

        # 内置常见厂商数据库
        common_vendors = {
            "00:00:00": "Xerox",
            "00:01:42": "QNAP",
            "00:0C:29": "VMware",
            "00:14:22": "Apple",
            "00:16:3E": "Amazon",
            "00:1E:06": "Cisco",
            "00:22:48": "Hewlett-Packard",
            "00:23:18": "Dell",
            "00:24:81": "Huawei",
            "00:30:67": "Sony",
            "00:50:56": "VMware",
            "00:60:97": "Brother",
            "00:80:48": "Microsoft",
            "00:90:4C": "Apple",
            "00:A0:C9": "Intel",
            "00:E0:4C": "Realtek",
            "08:00:27": "Oracle",
            "10:9A:DD": "Xiaomi",
            "18:5E:0F": "Huawei",
            "20:89:84": "TP-Link",
            "34:02:86": "Apple",
            "50:EB:F6": "TP-Link",
            "58:EB:7A": "Tenda",
            "68:1B:08": "HUAWEI",
            "74:E5:43": "TP-Link",
            "78:11:DC": "D-Link",
            "90:9A:4A": "Xiaomi",
            "A0:99:9B": "Apple",
            "B8:27:EB": "Raspberry Pi",
            "CC:46:D6": "TP-Link",
            "D4:EE:07": "HUAWEI",
            "E0:94:67": "TP-Link",
            "F0:2F:74": "TP-Link"
        }

        if mac_prefix in common_vendors:
            self.mac_vendors[mac_prefix] = common_vendors[mac_prefix]
            return common_vendors[mac_prefix]

        return "未知"

    def resolve_hostname(self, ip):
        """解析IP地址对应的主机名"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.timeout):
            return "未知"

    def detect_os(self, ip):
        """检测操作系统类型"""
        if not self.nm:
            return "未知"

        try:
            logger.debug(f"正在检测 {ip} 的操作系统")
            self.nm.scan(ip, arguments='-O -n -PE -PS21,22,23,80,443,3389')

            if ip in self.nm.all_hosts():
                os_info = self.nm[ip].get('osclass', [{}])[0]
                if os_info:
                    return f"{os_info.get('osfamily', '未知')} {os_info.get('osgen', '')}".strip()

                # 基于开放端口的简单推测
                ports = self.nm[ip].get('tcp', {})
                if 3389 in ports:  # RDP端口
                    return "可能是Windows"
                elif 22 in ports:  # SSH端口
                    return "可能是Linux/Unix"
                elif 5900 in ports:  # VNC端口
                    return "可能是服务器/嵌入式设备"
        except Exception as e:
            logger.debug(f"检测 {ip} 操作系统失败: {e}")

        return "未知"

    def get_open_ports(self, ip, top_ports=100):
        """获取开放端口信息"""
        if not self.nm:
            return []

        try:
            logger.debug(f"正在扫描 {ip} 的开放端口")
            self.nm.scan(ip, arguments=f'-n -sT --top-ports {top_ports}')

            if ip in self.nm.all_hosts():
                tcp_ports = self.nm[ip].get('tcp', {})
                open_ports = []

                for port, info in tcp_ports.items():
                    if info['state'] == 'open':
                        service = info.get('name', 'unknown')
                        product = info.get('product', '')
                        version = info.get('version', '')
                        service_info = f"{service}"
                        if product:
                            service_info += f" ({product})"
                        if version:
                            service_info += f" v{version}"

                        open_ports.append({
                            'port': port,
                            'service': service_info,
                            'state': info['state']
                        })

                return sorted(open_ports, key=lambda x: x['port'])
        except Exception as e:
            logger.debug(f"扫描 {ip} 端口失败: {e}")

        return []

    def identify_device_type(self, ip, hostname, mac, open_ports):
        """识别设备类型"""
        # 检查是否为网关
        if self.selected_interface and ip == self.selected_interface['gateway']:
            return "网关/路由器"

        # 基于主机名识别
        hostname_lower = hostname.lower()
        if 'printer' in hostname_lower or 'print' in hostname_lower:
            return "打印机"
        if 'camera' in hostname_lower or 'cam' in hostname_lower:
            return "网络摄像头"
        if 'nas' in hostname_lower:
            return "网络存储(NAS)"
        if 'server' in hostname_lower:
            return "服务器"
        if 'ap' in hostname_lower or 'accesspoint' in hostname_lower:
            return "无线接入点"

        # 基于开放端口识别
        port_numbers = [p['port'] for p in open_ports]
        if 80 in port_numbers and 443 in port_numbers and 22 not in port_numbers:
            return "网络设备"
        if 5900 in port_numbers or 3389 in port_numbers:
            return "远程桌面设备"
        if 631 in port_numbers:  # CUPS打印服务
            return "打印机"
        if 21 in port_numbers and 20 in port_numbers:  # FTP服务
            return "文件服务器"

        # 基于厂商识别
        vendor = self.get_mac_vendor(mac)
        vendor_lower = vendor.lower()
        if 'apple' in vendor_lower:
            return "Apple设备(iPhone/Mac等)"
        if 'xiaomi' in vendor_lower or 'huawei' in vendor_lower or 'samsung' in vendor_lower:
            return "移动设备/智能手机"
        if 'hp' in vendor_lower or 'hewlett' in vendor_lower:
            return "HP设备(可能是打印机/电脑)"
        if 'dell' in vendor_lower:
            return "戴尔电脑/服务器"
        if 'tp-link' in vendor_lower or 'd-link' in vendor_lower:
            return "网络设备"

        return "未知设备"

    def scan_ip(self, ip):
        """扫描单个IP的详细信息"""
        try:
            # 基础连通性检测
            ping_result = self.ping_ip(ip)
            if not ping_result['alive']:
                return None

            # 获取MAC地址
            mac = self.arp_table.get(ip, "未知")

            # 解析主机名
            hostname = self.resolve_hostname(ip)

            # 获取厂商信息
            vendor = self.get_mac_vendor(mac)

            # 扫描开放端口
            open_ports = self.get_open_ports(ip, self.args.top_ports) if self.args.full_scan else []

            # 检测操作系统
            os_info = self.detect_os(ip) if self.args.full_scan else "未扫描"

            # 识别设备类型
            device_type = self.identify_device_type(ip, hostname, mac, open_ports)

            # 整理结果
            result = {
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'vendor': vendor,
                'avg_rtt': ping_result['avg_rtt'],
                'os': os_info,
                'device_type': device_type,
                'open_ports': open_ports,
                'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            with self.lock:
                self.scan_results[ip] = result

            logger.debug(f"完成 {ip} 扫描")
            return result

        except Exception as e:
            logger.error(f"扫描 {ip} 时出错: {e}")
            return None

    def scan_network(self, network):
        """扫描整个网络"""
        try:
            logger.info(f"开始扫描网络: {network['cidr']}")
            start_time = time.time()

            # 首先更新ARP表
            self.update_arp_table()

            # 获取所有IP地址
            ip_network = ipaddress.IPv4Network(network['cidr'], strict=False)
            total_ips = len(list(ip_network.hosts()))
            logger.info(f"网络 {network['cidr']} 包含 {total_ips} 个可扫描IP")

            # 并发扫描
            progress = 0
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                futures = {executor.submit(self.scan_ip, str(ip)): str(ip) for ip in ip_network.hosts()}

                for future in as_completed(futures):
                    progress += 1
                    if progress % 10 == 0 or progress == total_ips:
                        elapsed = time.time() - start_time
                        ips_per_sec = progress / elapsed if elapsed > 0 else 0
                        logger.info(
                            f"扫描进度: {progress}/{total_ips} ({progress / total_ips * 100:.1f}%) - {ips_per_sec:.1f} IP/秒")

            elapsed_time = time.time() - start_time
            logger.info(f"扫描完成，耗时 {elapsed_time:.2f} 秒")
            logger.info(f"发现 {len(self.scan_results)} 个活跃设备")

            return self.scan_results

        except Exception as e:
            logger.error(f"网络扫描失败: {e}")
            return {}

    def generate_report(self):
        """生成扫描报告"""
        if not self.scan_results:
            logger.info("没有扫描结果可生成报告")
            return

        # 按IP地址排序
        sorted_ips = sorted(self.scan_results.keys(), key=lambda x: ipaddress.IPv4Address(x))

        # 打印表格摘要
        print("\n===== 局域网设备扫描结果 =====")
        table = PrettyTable()
        table.field_names = ["IP地址", "MAC地址", "主机名", "厂商", "设备类型", "平均响应时间(ms)"]

        for ip in sorted_ips:
            device = self.scan_results[ip]
            table.add_row([
                ip,
                device['mac'],
                device['hostname'],
                device['vendor'],
                device['device_type'],
                f"{device['avg_rtt']:.1f}" if device['avg_rtt'] else "N/A"
            ])

        print(table)

        # 保存详细报告
        if self.args.output:
            output_file = self.args.output
            try:
                if output_file.endswith('.csv'):
                    self.save_csv_report(sorted_ips, output_file)
                elif output_file.endswith('.json'):
                    self.save_json_report(sorted_ips, output_file)
                else:
                    self.save_text_report(sorted_ips, output_file)
                logger.info(f"详细报告已保存至 {output_file}")
            except Exception as e:
                logger.error(f"保存报告失败: {e}")

        # 显示设备类型分布
        self.show_device_distribution()

    def save_csv_report(self, sorted_ips, filename):
        """保存CSV格式报告"""
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # 写入表头
            writer.writerow([
                'IP地址', 'MAC地址', '主机名', '厂商', '设备类型',
                '操作系统', '平均响应时间(ms)', '开放端口', '最后发现时间'
            ])

            # 写入数据
            for ip in sorted_ips:
                device = self.scan_results[ip]
                ports = ', '.join([f"{p['port']}/{p['service']}" for p in device['open_ports']])
                writer.writerow([
                    ip,
                    device['mac'],
                    device['hostname'],
                    device['vendor'],
                    device['device_type'],
                    device['os'],
                    device['avg_rtt'] or 'N/A',
                    ports,
                    device['last_seen']
                ])

    def save_json_report(self, sorted_ips, filename):
        """保存JSON格式报告"""
        report_data = {
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'network': self.selected_interface['cidr'],
            'total_devices': len(sorted_ips),
            'devices': [self.scan_results[ip] for ip in sorted_ips]
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, ensure_ascii=False, indent=2)

    def save_text_report(self, sorted_ips, filename):
        """保存文本格式报告"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"局域网设备扫描报告 - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"扫描网络: {self.selected_interface['cidr']}\n")
            f.write(f"发现设备总数: {len(sorted_ips)}\n\n")

            for ip in sorted_ips:
                device = self.scan_results[ip]
                f.write(f"IP地址: {ip}\n")
                f.write(f"  MAC地址: {device['mac']}\n")
                f.write(f"  主机名: {device['hostname']}\n")
                f.write(f"  厂商: {device['vendor']}\n")
                f.write(f"  设备类型: {device['device_type']}\n")
                f.write(f"  操作系统: {device['os']}\n")
                f.write(
                    f"  平均响应时间: {device['avg_rtt']:.1f}ms\n" if device['avg_rtt'] else "  平均响应时间: N/A\n")

                if device['open_ports']:
                    f.write(f"  开放端口: {len(device['open_ports'])}\n")
                    for port in device['open_ports']:
                        f.write(f"    {port['port']}: {port['service']} ({port['state']})\n")

                f.write(f"  最后发现时间: {device['last_seen']}\n\n")

    def show_device_distribution(self):
        """显示设备类型分布"""
        distribution = defaultdict(int)
        for device in self.scan_results.values():
            distribution[device['device_type']] += 1

        print("\n===== 设备类型分布 =====")
        table = PrettyTable()
        table.field_names = ["设备类型", "数量", "占比"]

        total = len(self.scan_results)
        for device_type, count in sorted(distribution.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total) * 100
            table.add_row([device_type, count, f"{percentage:.1f}%"])

        print(table)

    def run(self):
        """运行扫描流程"""
        # 检查权限
        if not self.is_admin():
            logger.warning("建议以管理员权限运行，以获取更准确的ARP表和扫描结果")
            if input("是否继续? (y/n) ").lower() != 'y':
                return

        # 选择网络接口
        self.selected_interface = self.select_interface()
        if not self.selected_interface:
            return

        # 执行扫描
        self.scan_network(self.selected_interface)

        # 保存MAC厂商缓存
        self.save_mac_vendor_cache()

        # 生成报告
        self.generate_report()


if __name__ == "__main__":
    # 命令行参数解析
    parser = argparse.ArgumentParser(description='高级局域网设备扫描工具')
    parser.add_argument('-f', '--full-scan', action='store_true', help='执行全面扫描(包括端口和OS检测)')
    parser.add_argument('-p', '--top-ports', type=int, default=100, help='全扫描时检测的top端口数量(默认100)')
    parser.add_argument('-o', '--output', help='输出报告文件(支持.csv, .json, .txt)')

    args = parser.parse_args()

    # 处理Windows平台的编码问题
    if platform.system() == "Windows":
        import ctypes

        ctypes.windll.kernel32.SetConsoleOutputCP(65001)

    # 运行扫描器
    scanner = AdvancedLANScanner(args)
    scanner.run()
