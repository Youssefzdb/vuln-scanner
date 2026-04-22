#!/usr/bin/env python3
"""Port Scanner Module"""
import socket
import threading
from queue import Queue

class PortScanner:
    def __init__(self, target, port_range="1-1024", threads=100):
        self.target = target
        self.threads = threads
        self.open_ports = []
        self.queue = Queue()
        start, end = map(int, port_range.split("-"))
        self.ports = range(start, end + 1)

    def _scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                except:
                    banner = ""
                self.open_ports.append({"port": port, "banner": banner})
                print(f"[+] Port {port} OPEN {banner}")
            sock.close()
        except:
            pass

    def _worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            self._scan_port(port)
            self.queue.task_done()

    def scan(self):
        print(f"[*] Scanning ports on {self.target}...")
        for port in self.ports:
            self.queue.put(port)
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self._worker)
            t.daemon = True
            t.start()
            threads.append(t)
        self.queue.join()
        print(f"[+] Found {len(self.open_ports)} open ports")
        return self.open_ports
