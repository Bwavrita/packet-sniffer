import threading
from src.models.vulnerable_sniffer import VulnerableSniffer
from src.models.ui import VulnerabilityDashboard

DEBUG = False
PATH = ['src/pcaps/http.pcap', 'src/pcaps/ftp.pcap'] 

def main():
    sniffer = VulnerableSniffer(path_files=PATH, interface='wg0')
    
    if DEBUG:
        print("Debug mode enabled: Processing pcap files")
        sniffer.run_debug()
    else:
        print("Live capture mode enabled: Starting packet sniffer")
        sniffer_thread = threading.Thread(target=sniffer.run, daemon=True)
        sniffer_thread.start()
        
    dashboard = VulnerabilityDashboard(
        vulnerabilities=sniffer.vulnerabilities,
        http_packets=sniffer.http_packets,
        ftp_packets=sniffer.ftp_packets,
        port_scan_packets_window_time=sniffer.port_scan_packets_window_time,
        port_scan_packets_stateful=sniffer.port_scan_packets_stateful
    )
    
    app = dashboard.create_dashboard()
    
    app.run(debug=True, use_reloader=False)

if __name__ == '__main__':
    main()