import pyshark
import re

from pyshark import capture
import asyncio
from collections import defaultdict, deque
from pathlib import Path
import shutil
import tempfile
import time

class VulnerableSniffer:
    def __init__(self, path_file: str='', time_window: int=60, port_threshold: int=4000, interface: str='wlp0s20f3'):
        self.path_file = path_file
        self.vulnerabilities = {
            'http': 0,
            'ftp': 0,
            'port_scan_window_time': 0,
            'port_scan_stateful': 0
        }
        self.port_threshold = port_threshold
        self.time_window = time_window
        self.state = defaultdict(lambda: {"timestamps": deque(), "ports": set()})
        self.http_packets = [] # Details of HTTP packets
        self.ftp_packets = [] # Details of FTP packets
        self.port_scan_packets_window_time = [] # Details of port scans detected by time window
        self.port_scan_packets_stateful = [] # Details of port scans detected by stateful analysis
        self.connections = {} # Track connection
        self.stateful_alerts = {}
        self.active_window_scans = {}
        self.interface = interface

    def _prepare_event_loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop

    def run(self):
        print(f'[DEBUG] Starting live capture on interface {self.interface}')

        self._prepare_event_loop()

        capture_live = pyshark.LiveCapture(interface=self.interface)
        
        for packet in capture_live.sniff_continuously():
            self.process_packet(packet)

    def run_debug(self):
        print(f'[DEBUG] Starting debug capture')
        print(f'[DEBUG] Reading capture file: {self.path_file}')

        self._prepare_event_loop()

        temp_file = None

        try:
            try:
                capture = pyshark.FileCapture(self.path_file)
            except pyshark.capture.capture.TSharkCrashException:
                source_path = Path(self.path_file).resolve()
                with tempfile.NamedTemporaryFile(suffix=source_path.suffix, delete=False) as temp_handle:
                    temp_file = Path(temp_handle.name)

                shutil.copy2(source_path, temp_file)
                capture = pyshark.FileCapture(str(temp_file))

            for packet in capture:
                self.process_packet(packet)
        finally:
            if temp_file and temp_file.exists():
                temp_file.unlink()

    def process_packet(self, packet):
        try:
            if not hasattr(packet, 'ip'):
                return

            src = packet.ip.src
            
            if hasattr(packet, 'tcp'): # If packet has TCP layer, we can check for port scanning
                data_port = int(packet.tcp.dstport)
                self.detect_port_scan(src, data_port, packet)
                self._expire_connections()

            if 'HTTP' in packet:
                self._http_protocol(packet)

            if 'FTP' in packet:
                self._ftp_protocol(packet)

        except AttributeError as e:
            print(f'[ERROR] Attribute error while processing packet: {e}')

    def _register_stateful_alert(self, src, dst_port, type, now):
        key = (src, type)
    
        if key not in self.stateful_alerts:
            alert = {'Type': type, 'origin': src, 'ports': {dst_port}, 'last_updated': now}
            self.stateful_alerts[key] = alert
            self.port_scan_packets_stateful.append(alert)
            self.vulnerabilities['port_scan_stateful'] += 1
        else:
            self.stateful_alerts[key]['ports'].add(dst_port)
            self.stateful_alerts[key]['last_updated'] = now

    def detect_port_scan(self, src, dst_port, packet):
        now = time.time()

        # ── WINDOW TIME ───────────────────────────────────────────────
        entry = self.state[src]
        while entry["timestamps"] and now - entry["timestamps"][0] > self.time_window:
            entry["timestamps"].popleft()

        entry["timestamps"].append(now)
        entry["ports"].add(dst_port)

        if len(entry["ports"]) > self.port_threshold:
            if src not in self.active_window_scans:
                print(f'[TIME WINDOW] Port scan detected from {src}')
                self.vulnerabilities['port_scan_window_time'] += 1
                self.port_scan_packets_window_time.append({'Type': 'Time Window Scan', 'Origin': src, 'Ports': 'MMultiple'})
            
            self.active_window_scans[src] = now

        # ──  STATEFUL ───────────────────────────────────────────────
        if not hasattr(packet, 'tcp'):
            return

        flags = int(packet.tcp.flags, 16)
        key   = (src, dst_port)

        SYN = 0x02
        ACK = 0x10
        FIN = 0x01
        PSH = 0x08
        URG = 0x20

        # NULL scan 
        if flags == 0x00:
            print(f'[STATE] NULL scan detected from {src} on port {dst_port}')
            self._register_stateful_alert(src, dst_port, 'NULL Scan', now)
            return

        # XMAS scan — FIN + PSH + URG
        if (flags & (FIN | PSH | URG)) == (FIN | PSH | URG):
            print(f'[STATE] XMAS scan detected from {src} on port {dst_port}')
            self._register_stateful_alert(src, dst_port, 'XMAS Scan', now)
            return

        # FIN scan — FIN without ACK
        if (flags & FIN) and not (flags & ACK):
            print(f'[STATE] FIN scan detected from {src} on port {dst_port}')
            self._register_stateful_alert(src, dst_port, 'FIN Scan', now)
            return

        # SYN sem ACK
        if (flags & SYN) and not (flags & ACK):
            print(f'[DEBUG] Tracking SYN from {src} to port {dst_port}')
            self.connections[key] = {'state': 'SYN_SENT', 'time': now}
            return

        # ACK chegou
        if (flags & ACK) and key in self.connections:
            print(f'[DEBUG] ACK received for {src} on port {dst_port}; clearing connection state')
            del self.connections[key] # Connection established, remove from tracking
            return

    def _expire_connections(self):
        now     = time.time()
        timeout = 5.0
        
        expired = [k for k, v in self.connections.items()
                if v['state'] == 'SYN_SENT' and now - v['time'] > timeout]
        for key in expired:
            src, dst_port = key
            print(f'[STATE] Half-open scan detected from {src} on port {dst_port}')
            self._register_stateful_alert(src, dst_port, 'Half-Open Scan (SYN Sem ACK)', now)
            del self.connections[key]
            
        expired_alerts = [k for k, v in self.stateful_alerts.items() if now - v['last_updated'] > self.time_window]
        for k in expired_alerts:
            del self.stateful_alerts[k]

        expired_window_scans = [src for src, last_updated in self.active_window_scans.items() if now - last_updated > self.time_window]
        for src in expired_window_scans:
            del self.active_window_scans[src]
            if src in self.state:
                self.state[src]["timestamps"].clear()
                self.state[src]["ports"].clear()

    def _http_protocol(self, packet):
        keywords_vulnerable = ['usuario', 'user', 'senha', 'password']

        print('Detected HTTP protocol')

        http_layer = packet.http

        print(f'ID package: {packet.number}')
        print(f'Source IP address: {packet.ip.src}')
        print(f'Destination IP address: {packet.ip.dst}')

        print(f'HTTP method: {http_layer.get_field_value("request_method")}')
        print(f'Host: {http_layer.get_field_value("host")}')
        print(f'URL: {http_layer.get_field_value("request_full_uri")}')

        # View HTML content
        if hasattr(http_layer, 'file_data') and http_layer.file_data:
            try:
                html_content = bytes.fromhex(http_layer.file_data.replace(':', '')).decode('utf-8', errors='replace')
                print(f'HTML content:\n{html_content}')

                # Search if content have keywords vulnerable
                for keyword in keywords_vulnerable:
                    if re.search(keyword, html_content, re.IGNORECASE):
                        print(f'Found keyword: {keyword}')
                        self.vulnerabilities['http'] += 1
                        self.http_packets.append({
                            'id': packet.number,
                            'src_ip': packet.ip.src,
                            'dst_ip': packet.ip.dst,
                            'method': http_layer.get_field_value("request_method"),
                            'host': http_layer.get_field_value("host"),
                            'uri': http_layer.get_field_value("request_full_uri"),
                            'content': html_content
                        })

            except ValueError as ve:
                print("The package haven't layer HTML")

        print('------------------------------------')

    def _ftp_protocol(self, packet):

        # Regular expression to find email pattern
        email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
                                
        print('Detected FTP protocol')

        ftp_layer = packet.ftp
        print(f'ID package: {packet.number}')
        
        if hasattr(ftp_layer, 'request_command'):
            print(f'FTP command: {ftp_layer.request_command}')

        if hasattr(ftp_layer, 'request_arg'):
            print(f'FTP argument: {ftp_layer.request_arg}')

            # Search if arguments have email
            if email_pattern.search(ftp_layer.request_arg):
                print(f'Found email address: {ftp_layer.request_arg}')
                self.vulnerabilities['ftp'] += 1
                self.ftp_packets.append({
                    'id': packet.number,
                    'command': ftp_layer.request_command,
                    'arg': ftp_layer.request_arg
                })

        if hasattr(ftp_layer, 'response_code'):
            print(f'FTP response code: {ftp_layer.response_code}')

        if hasattr(ftp_layer, 'response_arg'):
            print(f'FTP response arg: {ftp_layer.response_arg}')

        print('------------------------------------')