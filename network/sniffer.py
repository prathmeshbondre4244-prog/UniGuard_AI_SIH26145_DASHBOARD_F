import threading
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, ICMP

class FlowTable:
    def __init__(self):
        self.lock = threading.Lock()
        self.flows = {}
        self.source_ports = defaultdict(set)
        self.source_hosts = defaultdict(set)

    def _key(self, pkt):
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else str(pkt[IP].proto)
        sport = int(getattr(pkt[TCP], "sport", 0)) if TCP in pkt else int(getattr(pkt[UDP], "sport", 0)) if UDP in pkt else 0
        dport = int(getattr(pkt[TCP], "dport", 0)) if TCP in pkt else int(getattr(pkt[UDP], "dport", 0)) if UDP in pkt else 0
        return (pkt[IP].src, pkt[IP].dst, proto, sport, dport)

    def add(self, pkt):
        if IP not in pkt:
            return
        now = time.time()
        key = self._key(pkt)
        src, dst, proto, sport, dport = key
        size = len(pkt)

        with self.lock:
            f = self.flows.setdefault(key, {
                "source": src,
                "destination": dst,
                "protocol": proto,
                "source_port": sport,
                "destination_port": dport,
                "start": now,
                "last": now,
                "packet_count": 0,
                "byte_count": 0,
                "sizes": [],
                "times": [],
                "failures": 0,
            })
            if f["packet_count"] > 0:
                f["times"].append(now - f["last"])
            f["last"] = now
            f["packet_count"] += 1
            f["byte_count"] += size
            f["sizes"].append(size)

            # Transparent TCP failure indicator: SYN/RST activity.
            if TCP in pkt:
                flags = str(pkt[TCP].flags)
                if "R" in flags:
                    f["failures"] += 1

            self.source_ports[src].add(dport)
            self.source_hosts[src].add(dst)

    def snapshot(self):
        with self.lock:
            items = list(self.flows.items())
            self.flows.clear()
            self.source_ports.clear()
            self.source_hosts.clear()

        out = []
        for key, f in items:
            duration = max(f["last"] - f["start"], 0.001)
            sizes = f["sizes"] or [0]
            intervals = f["times"] or [duration / max(f["packet_count"], 1)]
            out.append({
                "source": f["source"],
                "destination": f["destination"],
                "protocol": f["protocol"],
                "source_port": f["source_port"],
                "destination_port": f["destination_port"],
                "packet_count": f["packet_count"],
                "byte_count": f["byte_count"],
                "duration": duration,
                "packets_per_sec": f["packet_count"] / duration,
                "bytes_per_sec": f["byte_count"] / duration,
                "avg_packet_size": sum(sizes) / len(sizes),
                "min_packet_size": min(sizes),
                "max_packet_size": max(sizes),
                "inter_arrival_mean": sum(intervals) / len(intervals),
                "inter_arrival_std": _std(intervals),
                # These are conservative per-flow defaults; source-level aggregation
                # is handled by the alert rules in the backend.
                "destination_port_diversity": 1,
                "destination_host_diversity": 1,
                "connection_failure_rate": f["failures"] / max(f["packet_count"], 1),
            })
        return out

def _std(values):
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return (sum((v - mean) ** 2 for v in values) / len(values)) ** 0.5


class PassiveSniffer:
    def __init__(self, flow_table):
        self.flow_table = flow_table
        self.thread = None
        self.running = False
        self.interface = None

    def start(self, interface):
        if self.running:
            return
        self.interface = interface
        self.running = True

        def run():
            try:
                sniff(
                    iface=interface,
                    prn=self.flow_table.add,
                    store=False,
                    stop_filter=lambda _: not self.running,
                )
            except Exception as exc:
                self.running = False
                print("Capture error:", exc)

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
