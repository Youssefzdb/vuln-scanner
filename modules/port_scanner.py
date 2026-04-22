import socket
import threading
from colorama import Fore, Style

class PortScanner:
    def __init__(self, target, port_range="1-1024"):
        self.target = target
        self.start, self.end = map(int, port_range.split("-"))
        self.open_ports = []
        self.lock = threading.Lock()

    def _scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((self.target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                with self.lock:
                    self.open_ports.append({"port": port, "service": service, "state": "open"})
                    print(f"{Fore.GREEN}[+] Port {port}/tcp open ({service}){Style.RESET_ALL}")
            s.close()
        except Exception:
            pass

    def scan(self):
        print(f"[*] Scanning ports {self.start}-{self.end} on {self.target}...")
        threads = []
        for port in range(self.start, self.end + 1):
            t = threading.Thread(target=self._scan_port, args=(port,))
            threads.append(t)
            t.start()
            if len(threads) >= 100:
                for t in threads:
                    t.join()
                threads = []
        for t in threads:
            t.join()
        print(f"[+] Found {len(self.open_ports)} open ports")
        return self.open_ports

