"""
Flow tracker: rebuilds bidirectional connection records from raw packets,
using the same columns as the TON_IoT network dataset (Zeek-style conn log).
"""

from scapy.all import IP, TCP, UDP, ICMP

IDLE_TIMEOUT = 3.0       # seconds without packets -> flow is finished
MAX_FLOW_AGE = 30.0      # long flows are cut into snapshots of this length
CLOSED_GRACE = 0.5       # after FIN/RST wait a little for the last packets

SYN, FIN, RST, ACK = 0x02, 0x01, 0x04, 0x10


class Flow:
    __slots__ = ('orig_ip', 'orig_port', 'resp_ip', 'resp_port', 'proto',
                 'start', 'last', 'src_pkts', 'dst_pkts', 'src_bytes',
                 'dst_bytes', 'src_ip_bytes', 'dst_ip_bytes', 'syn_o',
                 'synack_r', 'fin_o', 'fin_r', 'rst_o', 'rst_r')

    def __init__(self, orig_ip, orig_port, resp_ip, resp_port, proto, now):
        self.orig_ip, self.orig_port = orig_ip, orig_port
        self.resp_ip, self.resp_port = resp_ip, resp_port
        self.proto = proto
        self.start = self.last = now
        self.src_pkts = self.dst_pkts = 0
        self.src_bytes = self.dst_bytes = 0
        self.src_ip_bytes = self.dst_ip_bytes = 0
        self.syn_o = self.synack_r = False
        self.fin_o = self.fin_r = self.rst_o = self.rst_r = False

    def conn_state(self):
        if self.proto != 'tcp':
            return 'SF' if self.dst_pkts > 0 else 'S0'
        if not self.syn_o:
            return 'OTH'                      # connection seen mid-stream
        if not self.synack_r:
            if self.rst_r:
                return 'REJ'
            if self.fin_o:
                return 'SH'
            return 'S0'
        if self.rst_o:
            return 'RSTO'
        if self.rst_r:
            return 'RSTR'
        if self.fin_o and self.fin_r:
            return 'SF'
        if self.fin_o:
            return 'S2'
        if self.fin_r:
            return 'S3'
        return 'S1'

    def closed(self):
        return self.rst_o or self.rst_r or (self.fin_o and self.fin_r)

    def to_record(self):
        return {
            'src_ip': self.orig_ip, 'src_port': self.orig_port,
            'dst_ip': self.resp_ip, 'dst_port': self.resp_port,
            'proto': self.proto,
            'duration': round(self.last - self.start, 6),
            'src_bytes': self.src_bytes, 'dst_bytes': self.dst_bytes,
            'conn_state': self.conn_state(),
            'src_pkts': self.src_pkts, 'dst_pkts': self.dst_pkts,
            'src_ip_bytes': self.src_ip_bytes, 'dst_ip_bytes': self.dst_ip_bytes,
            'end_time': self.last,
        }


class FlowTracker:
    """Not thread-safe by itself - the caller holds a lock."""

    def __init__(self):
        self.flows = {}

    @staticmethod
    def parse(pkt):
        """Return (src, dst, sport, dport, proto, payload_len, ip_len, flags) or None."""
        if IP not in pkt:
            return None
        ip = pkt[IP]
        if TCP in pkt:
            l4 = pkt[TCP]
            return (ip.src, ip.dst, int(l4.sport), int(l4.dport), 'tcp',
                    len(l4.payload), int(ip.len), int(l4.flags))
        if UDP in pkt:
            l4 = pkt[UDP]
            return (ip.src, ip.dst, int(l4.sport), int(l4.dport), 'udp',
                    len(l4.payload), int(ip.len), 0)
        if ICMP in pkt:
            return (ip.src, ip.dst, 0, 0, 'icmp',
                    len(pkt[ICMP].payload), int(ip.len), 0)
        return None

    def process(self, parsed, now):
        """Add one packet. Returns True when it started a new flow."""
        src, dst, sport, dport, proto, payload, ip_len, flags = parsed
        a, b = (src, sport), (dst, dport)
        key = (proto, a, b) if a <= b else (proto, b, a)

        flow = self.flows.get(key)
        is_new = flow is None
        if is_new:
            flow = Flow(src, sport, dst, dport, proto, now)
            self.flows[key] = flow

        flow.last = now
        from_orig = (src == flow.orig_ip and sport == flow.orig_port)
        if from_orig:
            flow.src_pkts += 1
            flow.src_bytes += payload
            flow.src_ip_bytes += ip_len
        else:
            flow.dst_pkts += 1
            flow.dst_bytes += payload
            flow.dst_ip_bytes += ip_len

        if proto == 'tcp':
            if from_orig:
                if flags & SYN and not flags & ACK:
                    flow.syn_o = True
                if flags & FIN:
                    flow.fin_o = True
                if flags & RST:
                    flow.rst_o = True
            else:
                if flags & SYN and flags & ACK:
                    flow.synack_r = True
                if flags & FIN:
                    flow.fin_r = True
                if flags & RST:
                    flow.rst_r = True
        return is_new

    def expire(self, now, force=False):
        """Remove and return finished flows as records."""
        done = []
        for key, f in list(self.flows.items()):
            idle = now - f.last
            if (force or idle >= IDLE_TIMEOUT or (now - f.start) >= MAX_FLOW_AGE
                    or (f.closed() and idle >= CLOSED_GRACE)):
                done.append(f.to_record())
                del self.flows[key]
        return done
