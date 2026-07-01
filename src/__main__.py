import threading
from src.models.vulnerable_sniffer import VulnerableSniffer
from src.models.ui import VulnerabilityDashboard

DEBUG = True  # Set to True to enable debug mode and process pcap files instead of live capture
PATH = "src/pcap_files/PORT_SCAN_ALL_PORTS.pcapng" 
PATH_4000 = "src/pcap_files/PORT_SCAN_4000_PORTS.pcapng" 

def main():
    
    if DEBUG:
        sniffer = VulnerableSniffer(path_file=PATH_4000 ,port_threshold=3000 ,interface='wlp0s20f3') # To test with a smaller pcap file, you can use PATH_4000 and port_threshold=4000
        print("Debug mode enabled: Processing pcap files")
        sniffer_thread = threading.Thread(target=sniffer.run_debug, daemon=True)
        sniffer_thread.start()
    else:
        sniffer = VulnerableSniffer(path_file=PATH ,interface='wlp0s20f3')  # Replace with your network interface name
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