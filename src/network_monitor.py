"""
Network Monitor Module - Captures Real Network Traffic
"""

import socket
import subprocess
import threading
import time
import json
from datetime import datetime

# Try to import network libraries
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except:
    NETIFACES_AVAILABLE = False
    print("[WARNING] netifaces not available. Install: pip install netifaces")

try:
    import psutil
    PSUTIL_AVAILABLE = True
except:
    PSUTIL_AVAILABLE = False
    print("[WARNING] psutil not available. Install: pip install psutil")

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except:
    SCAPY_AVAILABLE = False
    print("[WARNING] scapy not available. Install: pip install scapy")

try:
    import nmap
    NMAP_AVAILABLE = True
except:
    NMAP_AVAILABLE = False
    print("[WARNING] python-nmap not available. Install: pip install python-nmap")
    print("[WARNING] Also install Nmap from: https://nmap.org/download.html")


class NetworkMonitor:
    """
    Real-time network monitor for intrusion detection
    """
    
    def __init__(self):
        self.hostname = socket.gethostname()
        self.local_ip = socket.gethostbyname(self.hostname)
        self.wifi_name = None
        self.connected_devices = []
        self.network_traffic = []
        self.monitoring = False
        self.packet_callback = None
        self.sniffer_thread = None
        
        # Get network info on startup
        self.get_network_info()
    
    def get_network_info(self):
        """Get WiFi name, IP, hostname"""
        info = {
            'hostname': self.hostname,
            'local_ip': self.local_ip,
            'wifi': 'Unknown',
            'mac_address': None
        }
        
        # Get WiFi SSID on Windows
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, shell=True
            )
            for line in result.stdout.split('\n'):
                if 'SSID' in line and 'BSSID' not in line:
                    info['wifi'] = line.split(':')[1].strip()
                    break
        except:
            pass
        
        # Get MAC address
        try:
            import uuid
            info['mac_address'] = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) 
                                           for ele in range(0, 8*6, 8)][::-1])
        except:
            pass
        
        self.wifi_name = info['wifi']
        return info
    
    def scan_connected_devices(self):
        """Scan network for connected devices"""
        devices = []
        
        if not NMAP_AVAILABLE:
            return [{'ip': self.local_ip, 'hostname': self.hostname, 'status': 'up'}]
        
        try:
            # Get network prefix (e.g., 192.168.1.0/24)
            network = '.'.join(self.local_ip.split('.')[:-1]) + '.0/24'
            
            nm = nmap.PortScanner()
            nm.scan(network, arguments='-sn')
            
            for host in nm.all_hosts():
                devices.append({
                    'ip': host,
                    'hostname': nm[host].hostname() if nm[host].hostname() else 'Unknown',
                    'status': nm[host].state()
                })
        except Exception as e:
            print(f"[ERROR] Device scan failed: {e}")
            devices = [{'ip': self.local_ip, 'hostname': self.hostname, 'status': 'up'}]
        
        self.connected_devices = devices
        return devices
    
    def get_network_traffic_stats(self):
        """Get live network traffic statistics"""
        stats = {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets_sent': 0,
            'packets_recv': 0,
            'connections': 0
        }
        
        if PSUTIL_AVAILABLE:
            net_io = psutil.net_io_counters()
            stats['bytes_sent'] = net_io.bytes_sent
            stats['bytes_recv'] = net_io.bytes_recv
            stats['packets_sent'] = net_io.packets_sent
            stats['packets_recv'] = net_io.packets_recv
            
            # Count active connections
            try:
                connections = psutil.net_connections()
                stats['connections'] = len([c for c in connections if c.status == 'ESTABLISHED'])
            except:
                pass
        
        return stats
    
    def start_monitoring(self, packet_callback=None, iface=None):
        """Start capturing real network packets"""
        self.monitoring = True
        self.packet_callback = packet_callback
    
        if not SCAPY_AVAILABLE:
            print("[WARNING] Cannot capture packets - Scapy not installed")
            return False
    
    # Auto-detect active interface if not provided
        if iface is None:
            try:
                from scapy.arch.windows import get_windows_if_list
                interfaces = get_windows_if_list()
                print("[INFO] Available network interfaces:")
                for i, intf in enumerate(interfaces):
                    print(f"   {i}: {intf['name']}")
            
            # Try to auto-select the active WiFi/hotspot interface
                for intf in interfaces:
                    name = intf['name'].lower()
                    if 'wi-fi' in name or 'wireless' in name or 'wlan' in name:
                        iface = intf['name']
                        print(f"[INFO] Auto-selected interface: {iface}")
                        break
            
                if iface is None:
                    iface = interfaces[0]['name'] if interfaces else None
                    print(f"[INFO] Using default interface: {iface}")
            except Exception as e:
                print(f"[WARNING] Could not auto-detect interface: {e}")

        def capture_packets():
            try:
                # Sniff packets on specific interface
                sniff(prn=self.process_packet, store=0, timeout=1, iface=iface)
            except Exception as e:
                print(f"[ERROR] Packet capture error: {e}")
    
        def packet_loop():
            packet_count = 0
            while self.monitoring:
                capture_packets()
                packet_count += 1
                if packet_count % 10 == 0:
                    print(f"[INFO] Still monitoring on {iface}... ({len(self.network_traffic)} packets captured)")
                time.sleep(0.1)

        self.sniffer_thread = threading.Thread(target=packet_loop)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()

        print(f"[INFO] Monitoring started on interface: {iface}")
        return True
    
    def process_packet(self, packet):
        """Process each captured packet and detect threats"""
        if not self.monitoring:
            return
        
        try:
            # Extract packet info
            packet_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'protocol': 'Unknown',
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'size': len(packet)
            }
            
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                
                if TCP in packet:
                    packet_info['protocol'] = 'TCP'
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                elif UDP in packet:
                    packet_info['protocol'] = 'UDP'
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
            
            # Check for suspicious patterns
            threat = self.check_for_threats(packet_info)
            
            if threat:
                packet_info['threat'] = threat
            
            # Add to traffic log
            self.network_traffic.append(packet_info)
            if len(self.network_traffic) > 1000:
                self.network_traffic = self.network_traffic[-500:]
            
            # Call external callback if provided
            if self.packet_callback:
                self.packet_callback(packet_info)
                
        except Exception as e:
            pass
    
    def check_for_threats(self, packet):
        """Check packet for suspicious patterns"""
        threats = []
        
        # Check for port scan (many connections to different ports)
        # This is simplified - real detection would use your ML model
        
        # Check for suspicious ports
        suspicious_ports = [22, 23, 445, 3389, 5900, 8080]
        if packet.get('dst_port') in suspicious_ports:
            threats.append(f"Connection to suspicious port {packet['dst_port']}")
        
        # Check for unusual protocols
        if packet.get('protocol') == 'ICMP' and packet.get('size', 0) > 100:
            threats.append("Large ICMP packet - possible ping flood")
        
        # Check for many connections from same IP (simplified)
        # In real implementation, track connection counts
        
        return threats if threats else None
    
    def stop_monitoring(self):
        """Stop packet capture"""
        self.monitoring = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
    
    def get_network_summary(self):
        """Get complete network status summary"""
        stats = self.get_network_traffic_stats()
        
        return {
            'hostname': self.hostname,
            'local_ip': self.local_ip,
            'wifi': self.wifi_name,
            'connected_devices': self.scan_connected_devices(),
            'traffic_stats': stats,
            'recent_packets': self.network_traffic[-20:],
            'monitoring': self.monitoring
        }


# Test function
if __name__ == "__main__":
    monitor = NetworkMonitor()
    print("Network Monitor Test")
    print(f"Hostname: {monitor.hostname}")
    print(f"Local IP: {monitor.local_ip}")
    print(f"WiFi: {monitor.wifi_name}")
    print("Connected Devices:", monitor.scan_connected_devices())