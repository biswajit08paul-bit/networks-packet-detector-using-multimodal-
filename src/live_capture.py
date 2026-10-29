import os
import sys
import threading
import time
import socket
import subprocess
import re
from collections import defaultdict, deque
from datetime import datetime

import psutil
from scapy.all import ARP, Ether, IP, sniff, conf

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flow_features import MODELS_DIR
from flow_tracker import FlowTracker, IDLE_TIMEOUT
from live_detector import FlowClassifier, BehaviorDetector

MODEL_FILE = os.path.join(MODELS_DIR, 'flow_model.pkl')


class LiveCapture:
    def __init__(self, interface=None):
        self.local_ip = self._get_local_ip()
        self.gateway_ip = self._get_gateway_ip()
        self.subnet = self._get_subnet()

        # Enumerate interfaces
        self.available_interfaces = self.get_interfaces()
        # Default to first interface with valid non-loopback IP (e.g. Wi-Fi)
        default_iface = None
        for ifc in self.available_interfaces:
            if ifc['ip'] and ifc['ip'] != '127.0.0.1':
                default_iface = ifc['name']
                break
        if not default_iface and self.available_interfaces:
            default_iface = self.available_interfaces[0]['name']

        self.interface = interface or default_iface

        self.tracker = FlowTracker()
        try:
            self.classifier = FlowClassifier()
        except Exception as e:
            print(f"[WARNING] Classifier not loaded: {e}")
            self.classifier = None
        self.behavior = BehaviorDetector()

        self.lock = threading.Lock()
        self.monitoring = False
        self.sniffer_stop = threading.Event()
        self.capture_thread = None
        self.expire_thread = None
        self.fallback_thread = None
        self.last_error = None

        self.devices = {}
        self.alerts = []
        self.flow_count = 0
        self.classified_count = 0
        self.total_packets = 0
        self.total_bytes = 0

        self.discovered_devices = self.scan_network()
        now = time.time()
        for dev in self.discovered_devices:
            ip = dev['ip']
            is_local = (ip == self.local_ip)
            is_gw = (ip == self.gateway_ip)
            role = 'Host (You)' if is_local else ('Gateway' if is_gw else 'External')
            init_status = 'protected' if is_local else 'normal'

            self.devices[ip] = {
                'ip': ip,
                'mac': dev.get('mac', 'Unknown'),
                'hostname': dev.get('hostname', 'Unknown'),
                'role': role,
                'is_local': is_local,
                'packets_sent': 0,
                'packets_received': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'first_seen': now,
                'last_seen': now,
                'threats': 0,
                'status': init_status,
                'alerts': []
            }

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def _get_gateway_ip(self):
        try:
            out = subprocess.check_output('ipconfig', text=True, errors='ignore')
            matches = re.findall(r'Default Gateway[ .]*: ([\d\.]+)', out)
            for m in matches:
                if m and m != '0.0.0.0':
                    return m
        except Exception:
            pass
        return None

    def _get_subnet(self):
        parts = self.local_ip.split('.')
        return '.'.join(parts[:3]) + '.0/24'

    def get_interfaces(self):
        primary = []
        seen = set()
        ignore_keywords = ['filter', 'miniport', 'debugger', 'qos', 'npcap', 'teredo', '6to4', 'ip-https', 'ras async']

        try:
            from scapy.arch.windows import get_windows_if_list
            for w in get_windows_if_list():
                name = w.get('name', '')
                desc = w.get('description', '')
                full = (name + ' ' + desc).lower()
                if any(k in full for k in ignore_keywords):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                ips = w.get('ips', [])
                ipv4 = next((ip for ip in ips if '.' in ip and not ip.startswith('169.254')), None)
                primary.append({
                    'name': name,
                    'description': desc,
                    'ip': ipv4,
                    'mac': w.get('mac', '')
                })
        except Exception:
            pass

        # Fallback to psutil if empty
        if not primary:
            try:
                for ifname, addrs in psutil.net_if_addrs().items():
                    if any(k in ifname.lower() for k in ignore_keywords):
                        continue
                    ipv4 = None
                    mac = ''
                    for a in addrs:
                        if getattr(a.family, 'name', '') == 'AF_INET':
                            if not a.address.startswith('169.254'):
                                ipv4 = a.address
                        elif getattr(a.family, 'name', '') == 'AF_LINK':
                            mac = a.address
                    primary.append({
                        'name': ifname,
                        'description': ifname,
                        'ip': ipv4,
                        'mac': mac
                    })
            except Exception:
                pass

        # Sort so active interface with IP comes first
        primary.sort(key=lambda x: (x['ip'] is None, x['ip'] == '127.0.0.1'))
        return primary

    def scan_network(self):
        devices = []
        own_mac = self._get_own_mac()

        # Local device
        devices.append({
            'ip': self.local_ip,
            'mac': own_mac or 'Unknown',
            'hostname': socket.gethostname() + ' (This PC)'
        })

        # Gateway / Router
        if self.gateway_ip and self.gateway_ip != self.local_ip:
            devices.append({
                'ip': self.gateway_ip,
                'mac': 'Unknown',
                'hostname': 'Default Gateway / Router'
            })

        # Try Scapy ARP scan
        try:
            from scapy.all import srp
            arp = ARP(pdst=self.subnet)
            ether = Ether(dst='ff:ff:ff:ff:ff:ff')
            packet = ether / arp
            result, _ = srp(packet, timeout=2, verbose=0, iface=self.interface)
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'hostname': 'Unknown'
                })
        except Exception:
            pass

        seen = set()
        unique = []
        for d in devices:
            if d['ip'] not in seen:
                seen.add(d['ip'])
                unique.append(d)
        return unique

    def _get_own_mac(self):
        import uuid
        try:
            return ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 48, 8)][::-1])
        except Exception:
            return None

    def _update_device(self, ip, direction, pkt_len):
        with self.lock:
            now = time.time()
            if ip not in self.devices:
                is_local = (ip == self.local_ip)
                is_gw = (ip == self.gateway_ip)
                if is_local:
                    role = 'Host (You)'
                    hostname = socket.gethostname() + ' (This PC)'
                    initial_status = 'protected'
                elif is_gw:
                    role = 'Gateway'
                    hostname = 'Default Gateway / Router'
                    initial_status = 'normal'
                else:
                    role = 'External'
                    hostname = 'Unknown'
                    initial_status = 'normal'

                self.devices[ip] = {
                    'ip': ip,
                    'mac': 'Unknown',
                    'hostname': hostname,
                    'role': role,
                    'is_local': is_local,
                    'packets_sent': 0,
                    'packets_received': 0,
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'first_seen': now,
                    'last_seen': now,
                    'threats': 0,
                    'status': initial_status,
                    'alerts': []
                }
            d = self.devices[ip]
            d['last_seen'] = now

            if direction == 'sent':
                d['packets_sent'] += 1
                d['bytes_sent'] += pkt_len
            elif direction == 'received':
                d['packets_received'] += 1
                d['bytes_received'] += pkt_len
            else:
                d['packets_sent'] += 1
                d['bytes_sent'] += pkt_len

            self.total_packets += 1
            self.total_bytes += pkt_len

    def _raise_alert(self, src, dst, attack_type, detail, confidence):
        src_label = f"{src} (This PC)" if src == self.local_ip else src
        dst_label = f"{dst} (This PC)" if dst == self.local_ip else dst

        alert = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'type': attack_type,
            'src_ip': src,
            'dst_ip': dst,
            'src_label': src_label,
            'dst_label': dst_label,
            'detail': detail,
            'confidence': round(confidence, 3)
        }
        with self.lock:
            self.alerts.insert(0, alert)
            if len(self.alerts) > 100:
                self.alerts.pop()

            # Ensure attacker (src) is registered in devices
            now = time.time()
            if src not in self.devices:
                is_local_src = (src == self.local_ip)
                is_gw_src = (src == self.gateway_ip)
                role_src = 'Host (You)' if is_local_src else ('Gateway' if is_gw_src else 'External')
                self.devices[src] = {
                    'ip': src,
                    'mac': 'Unknown',
                    'hostname': 'External Threat Host' if role_src == 'External' else 'Unknown',
                    'role': role_src,
                    'is_local': is_local_src,
                    'packets_sent': 1,
                    'packets_received': 0,
                    'bytes_sent': 0,
                    'bytes_received': 0,
                    'first_seen': now,
                    'last_seen': now,
                    'threats': 0,
                    'status': 'normal',
                    'alerts': []
                }

            # Mark the actual ATTACKER (source of threat)
            if src != self.local_ip:
                self.devices[src]['threats'] += 1
                self.devices[src]['status'] = 'threat'
                self.devices[src]['alerts'].append(alert)
            else:
                # Outbound communication from local host should not mark PC as threat
                self.devices[src]['alerts'].append(alert)

            # The VICTIM / TARGET is dst.
            # Local PC is the PROTECTED host being defended, NEVER a threat!
            if dst in self.devices:
                if dst == self.local_ip:
                    self.devices[dst]['status'] = 'protected'
                elif dst != src and self.devices[dst]['threats'] == 0:
                    self.devices[dst]['status'] = 'normal'

    def _on_packet(self, pkt):
        if IP not in pkt:
            return
        now = time.time()
        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        pkt_len = int(ip_layer.len)

        if src == self.local_ip:
            direction = 'sent'
        elif dst == self.local_ip:
            direction = 'received'
        else:
            direction = 'other'

        self._update_device(src, direction, pkt_len)
        if dst != src:
            rev_dir = 'received' if direction == 'sent' else ('sent' if direction == 'received' else 'other')
            self._update_device(dst, rev_dir, pkt_len)

        parsed = self.tracker.parse(pkt)
        if parsed is None:
            return

        _s, _d, sport, dport, proto, payload, ip_len, flags = parsed
        is_new = self.tracker.process(parsed, now)

        if is_new and self.behavior:
            verdict = self.behavior.observe(now, src, dst, dport)
            if verdict:
                attack_type, detail = verdict
                self._raise_alert(src, dst, attack_type, detail, confidence=0.9)

    def _expire_loop(self):
        while not self.sniffer_stop.is_set():
            if self.sniffer_stop.wait(IDLE_TIMEOUT + 0.5):
                break
            now = time.time()
            records = self.tracker.expire(now)
            if not records:
                continue

            self.flow_count += len(records)

            if self.classifier:
                try:
                    results = self.classifier.classify(records)
                    self.classified_count += len(results)
                    for rec, res in zip(records, results):
                        if res['is_attack']:
                            self._raise_alert(
                                rec['src_ip'],
                                rec['dst_ip'],
                                res['attack_type'],
                                f"ML: {res['attack_type']} flow (score {res['attack_score']:.2f})",
                                confidence=res['confidence']
                            )
                except Exception as e:
                    print(f"[ERROR] Flow classification failed: {e}")

    def _fallback_loop(self):
        """
        Runs when Scapy raw sniffing is restricted by Windows/Npcap permissions.
        Reads real per-interface network counters so the dashboard dynamically
        reflects real bandwidth and packets, and runs flows through the ML model.
        Runs continuously until self.sniffer_stop is set.
        """
        nic_name = self.interface or 'Wi-Fi'
        last_io = None
        target_ip = self.gateway_ip or '8.8.8.8'

        while not self.sniffer_stop.is_set():
            try:
                per_nic = psutil.net_io_counters(pernic=True)
                # Find matching NIC
                matched_io = per_nic.get(nic_name)
                if not matched_io:
                    for k, v in per_nic.items():
                        if ('wi-fi' in k.lower() or 'wireless' in k.lower() or 'ethernet' in k.lower()) and v.bytes_sent > 0:
                            matched_io = v
                            break
                if not matched_io:
                    matched_io = psutil.net_io_counters()

                now = time.time()
                if last_io is not None and matched_io is not None:
                    delta_sent_pkts = max(0, matched_io.packets_sent - last_io.packets_sent)
                    delta_recv_pkts = max(0, matched_io.packets_recv - last_io.packets_recv)
                    delta_sent_bytes = max(0, matched_io.bytes_sent - last_io.bytes_sent)
                    delta_recv_bytes = max(0, matched_io.bytes_recv - last_io.bytes_recv)

                    tot_p = delta_sent_pkts + delta_recv_pkts
                    tot_b = delta_sent_bytes + delta_recv_bytes

                    if tot_p > 0 or tot_b > 0:
                        with self.lock:
                            self.total_packets += tot_p
                            self.total_bytes += tot_b

                            # Update local host (always protected)
                            if self.local_ip in self.devices:
                                ld = self.devices[self.local_ip]
                                ld['packets_sent'] += delta_sent_pkts
                                ld['packets_received'] += delta_recv_pkts
                                ld['bytes_sent'] += delta_sent_bytes
                                ld['bytes_received'] += delta_recv_bytes
                                ld['last_seen'] = now
                                ld['status'] = 'protected'

                            # Update gateway / target
                            if target_ip in self.devices:
                                gd = self.devices[target_ip]
                                gd['packets_sent'] += delta_recv_pkts
                                gd['packets_received'] += delta_sent_pkts
                                gd['bytes_sent'] += delta_recv_bytes
                                gd['bytes_received'] += delta_sent_bytes
                                gd['last_seen'] = now

                        # Synthesize clean baseline flow record for ML engine
                        sim_record = {
                            'dst_port': 443,
                            'duration': 1.0,
                            'src_bytes': delta_sent_bytes,
                            'dst_bytes': delta_recv_bytes,
                            'src_pkts': max(1, delta_sent_pkts),
                            'dst_pkts': max(1, delta_recv_pkts),
                            'src_ip_bytes': delta_sent_bytes + (max(1, delta_sent_pkts) * 40),
                            'dst_ip_bytes': delta_recv_bytes + (max(1, delta_recv_pkts) * 40),
                            'proto': 'tcp',
                            'conn_state': 'SF',
                            'src_ip': self.local_ip,
                            'dst_ip': target_ip
                        }
                        self.flow_count += 1
                        if self.classifier:
                            try:
                                res = self.classifier.classify([sim_record])
                                self.classified_count += len(res)
                                if res and res[0]['is_attack']:
                                    r = res[0]
                                    # Target is external, local is source
                                    self._raise_alert(
                                        target_ip,
                                        self.local_ip,
                                        r['attack_type'],
                                        f"ML: {r['attack_type']} anomaly detected (score {r['attack_score']:.2f})",
                                        confidence=r['confidence']
                                    )
                            except Exception:
                                pass

                last_io = matched_io
            except Exception as e:
                print(f"[DEBUG] Fallback monitor error: {e}")

            # Sleep in responsive chunks so stopping is immediate
            if self.sniffer_stop.wait(1.0):
                break

    def start(self):
        self.monitoring = True
        self.sniffer_stop.clear()
        self.last_error = None

        self.expire_thread = threading.Thread(target=self._expire_loop, daemon=True)
        self.expire_thread.start()

        def stop_filter(_pkt):
            return self.sniffer_stop.is_set()

        can_sniff = False
        try:
            # Quick 0.3s probe to test raw sniff capability on selected interface
            sniff(
                iface=self.interface,
                prn=self._on_packet,
                stop_filter=stop_filter,
                store=False,
                timeout=0.3
            )
            can_sniff = True
            print(f"[+] Raw packet sniffing active on interface: {self.interface}")
        except Exception as e:
            err_msg = str(e)
            print(f"[INFO] Raw packet sniffing note: {err_msg}")
            self.last_error = (
                "Notice: Running in Standard Monitoring mode (traffic & ML threat defense active). "
                "For raw deep-packet inspection, launch terminal as Administrator."
            )
            can_sniff = False

        if can_sniff:
            # Continuous raw packet capture loop
            while not self.sniffer_stop.is_set():
                try:
                    sniff(
                        iface=self.interface,
                        prn=self._on_packet,
                        stop_filter=stop_filter,
                        store=False,
                        timeout=1.0  # 1s chunk so sniffer_stop is checked regularly
                    )
                except Exception as e:
                    print(f"[WARN] Raw sniffer interrupted: {e}. Switching to fallback mode.")
                    can_sniff = False
                    break

        if not can_sniff and not self.sniffer_stop.is_set():
            # Continuous fallback traffic & ML monitor loop (keeps running until stopped)
            self._fallback_loop()

        self.monitoring = False

    def start_background(self):
        with self.lock:
            if self.monitoring:
                return True
            self.monitoring = True
            self.sniffer_stop.clear()
        self.capture_thread = threading.Thread(target=self.start, daemon=True)
        self.capture_thread.start()
        return True

    def stop(self):
        self.sniffer_stop.set()
        self.monitoring = False
        try:
            self.tracker.expire(time.time(), force=True)
        except Exception:
            pass

    def get_status(self):
        with self.lock:
            return {
                'monitoring': self.monitoring,
                'interface': self.interface,
                'local_ip': self.local_ip,
                'flow_count': self.flow_count,
                'classified_count': self.classified_count,
                'total_packets': self.total_packets,
                'total_bytes': self.total_bytes,
                'total_devices': len(self.devices),
                'total_alerts': len(self.alerts),
                'recent_alerts': list(self.alerts[:10]),
                'error': self.last_error
            }

    def get_devices(self):
        with self.lock:
            out = []
            for d in self.devices.values():
                total_pkts = d['packets_sent'] + d['packets_received']
                total_bytes = d['bytes_sent'] + d['bytes_received']
                is_local = (d.get('ip') == self.local_ip)
                is_gw = (d.get('ip') == self.gateway_ip)

                # Ensure local device is ALWAYS protected
                status = d.get('status', 'normal')
                if is_local:
                    status = 'protected'
                    role = 'Host (You)'
                elif is_gw:
                    role = 'Gateway'
                    if status != 'threat':
                        status = 'normal'
                else:
                    role = 'External'

                out.append({
                    'ip': d['ip'],
                    'mac': d['mac'],
                    'hostname': d['hostname'],
                    'role': role,
                    'is_local': is_local,
                    'packets_sent': d['packets_sent'],
                    'packets_received': d['packets_received'],
                    'total_packets': total_pkts,
                    'bytes_sent': d['bytes_sent'],
                    'bytes_received': d['bytes_received'],
                    'total_bytes': total_bytes,
                    'first_seen': datetime.fromtimestamp(d['first_seen']).strftime('%H:%M:%S'),
                    'last_seen': datetime.fromtimestamp(d['last_seen']).strftime('%H:%M:%S'),
                    'threats': d['threats'],
                    'status': status
                })
            # Local PC first, then Gateway, then by threat count and total packets descending
            out.sort(key=lambda x: (not x['is_local'], x['role'] != 'Gateway', -x['threats'], -x['total_packets']))
            return out

    def get_alerts(self):
        with self.lock:
            return list(self.alerts[:50])
