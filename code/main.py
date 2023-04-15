import feedparser
import wget
from datetime import datetime as dt
from zipfile import ZipFile as zp
import os
import shutil
import socket
import nmap
import json


# 1st step - check updates of CVE database
def check_updates_cve():
    global main_date
    update = False
    date = feedparser.parse("https://www.cve.org/AllResources/CveServices#cve-json-5").updated
    if date != main_date:
        update = True
        main_date = date

    if update:
        url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
        wget.download(url)  # => cvelistV5-main.zip
        with zp("cvelistV5-main.zip") as zf:
            zf.extractall("./")


# 2nd step - import CVE database
def import_cve():
    year = dt.now().year
    years = [str(year - 1), str(year)]  # install db's only for last and current years

    for f in os.listdir("./database"):
        os.remove(os.path.join("./database", f))

    for by_year in os.listdir("./cvelistV5-main/cves"):
        if by_year in years:
            for folders in os.listdir(f"./cvelistV5-main/cves/{by_year}"):
                if folders == "test.out":
                    continue
                for file in os.listdir(f"./cvelistV5-main/cves/{by_year}/{folders}"):
                    shutil.copy(f"./cvelistV5-main/cves/{by_year}/{folders}/{file}", "database")
        else:
            continue


# 3rd step - scan network & find devices
def nmap_scan():
    # gets IP address
    # IP range of the network from 192.168.0.0 to 192.168.0.255
    ip = socket.gethostbyname(socket.gethostname())

    # scans and founds all devices in network
    hosts = []
    scanner = nmap.PortScanner()
    scanner.scan(ip, arguments="-sn")
    for host in scanner.all_hosts():
        name = socket.gethostbyname_ex(socket.gethostname())[0]
        address = scanner[host]["addresses"]["ipv4"]
        if "mac" in address:
            mac = scanner[host]["addresses"]["mac"]
            hosts.append([name, mac, address])  # hosts of all devices in network
        else:
            hosts.append([name, "Не Изв.", address])


# ! 4th step - receive notification
def receive_notification():
    pass
    # >> json format file with information from notification


# ! 5th step - work with problem
def analyze_problem():
    pass
    # >> use json lib to analyze problem and find solution in cve database


# ! 6th step - send notification
def send_notification():
    pass
    # >> use plyer to send notifications


if __name__ == "__main__":
    main_date = ""
    if not os.path.exists("database"):
        os.mkdir("database")
    check_updates_cve()
    import_cve()
