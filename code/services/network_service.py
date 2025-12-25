import subprocess
from models.device import Device

class NetworkService:
    def scan(self, cidr="192.168.0.0/24"):
        result = subprocess.check_output(["nmap", "-sn", cidr], text=True)
        devices = []

        for line in result.splitlines():
            if "Nmap scan report for" in line:
                ip = line.split()[-1]
                devices.append(Device(ip, "Unknown", "Unknown", None))

        return devices
