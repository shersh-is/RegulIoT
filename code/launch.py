import sys
from PyQt5 import QtCore, uic
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QMessageBox, QTableWidgetItem, QVBoxLayout
from PyQt5.QtWebEngineWidgets import QWebEngineView
import feedparser
import wget
from datetime import datetime as dt
from zipfile import ZipFile as zp
import os
import shutil
import socket
import nmap
import json


class Application(QMainWindow):
    # sets main menu
    def menu(self):
        uic.loadUi("menu.ui", self)
        self.setWindowTitle("Меню")
        self.setWindowIcon(QIcon("icon.ico"))
        self.btn_ad.clicked.connect(self.run_btn_ad)
        self.btn_cfu.clicked.connect(self.run_btn_cfu)
        self.btn_db.clicked.connect(self.run_btn_db)
        self.btn_set.clicked.connect(self.run_btn_set)

    def __init__(self):
        super().__init__()
        self.menu()

    # full screen mode
    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_F11:
            if self.isFullScreen():
                self.showNormal()
            else:
                self.showFullScreen()

    # sends notifications to notify user
    def send_notifications(self):
        pass
        # analyzed device sends JSON format file

    # outside buttons
    # shows all devices
    def run_btn_ad(self):
        uic.loadUi("all_devices.ui", self)
        self.setWindowTitle("Все Устройства")
        self.setWindowIcon(QIcon("icon.ico"))
        self.btn_scan_net.clicked.connect(self.run_btn_scan_net)
        self.btn_check_device.clicked.connect(self.run_btn_check_device)
        self.btn_back.clicked.connect(self.menu)

    # checks updates of CVE-database + devices' updates (in future)
    def run_btn_cfu(self):
        uic.loadUi("check_for_updates.ui", self)
        self.setWindowTitle("Наличие обновлений")
        self.setWindowIcon(QIcon("icon.ico"))
        self.btn_check_upd.clicked.connect(self.run_check_upd)
        self.btn_back.clicked.connect(self.menu)

    # shows downloaded database
    def run_btn_db(self):
        uic.loadUi("db.ui", self)
        self.setWindowTitle("База Уязвимостей")
        self.setWindowIcon(QIcon("icon.ico"))
        for file_name in os.listdir("database"):
            self.list_db.addItem(file_name)
            # open file when clicked
        self.btn_back.clicked.connect(self.menu)

    # shows settings of device
    def run_btn_set(self):
        uic.loadUi("settings.ui", self)
        self.setWindowTitle("Параметры")
        self.setWindowIcon(QIcon("icon.ico"))
        self.btn_app_doc.clicked.connect(self.run_btn_app_doc)
        self.btn_tech_doc.clicked.connect(self.run_btn_tech_doc)
        self.btn_back.clicked.connect(self.menu)

    # inside buttons
    # check updates in btn_cfu
    def run_check_upd(self):
        uic.loadUi("check_for_updates_progress.ui", self)
        self.setWindowTitle("Наличие обновлений")
        self.setWindowIcon(QIcon("icon.ico"))

        """global main_date
        update = False
        date = feedparser.parse("https://www.cve.org/AllResources/CveServices#cve-json-5").updated
        if date != main_date:
            update = True
            main_date = date"""

        update = False
        if update:
            upd_message = QMessageBox()
            upd_message.setWindowTitle("Завершено")
            upd_message.setWindowIcon(QIcon("icon.ico"))
            upd_message.setText("Обнаружено новое обновление базы уязвимостей. Обновить?")
            upd_message.setIcon(QMessageBox.Warning)
            upd_message.addButton("Да", QMessageBox.YesRole)
            upd_message.addButton("Нет", QMessageBox.NoRole)

            answ = upd_message.exec_()  # 16384 => yes / 65536 => no
            # downloading new database for last and current years
            if answ == 16384:
                """url = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"
                wget.download(url)  # => cvelistV5-main.zip
                with zp("cvelistV5-main.zip") as zf:
                    zf.extractall("./")
                year = dt.now().year
                years = [str(year - 1), str(year)]  # install db's only for last and current years

                for f in os.listdir("./database"):
                    os.remove(os.path.join("./database", f))

                for by_year in os.listdir("./cvelistV5-main/cves"):
                    if by_year in years:
                        for folders in os.listdir(f"./cvelistV5-main/cves/{by_year}"):
                            for file in os.listdir(f"./cvelistV5-main/cves/{by_year}/{folders}"):
                                shutil.copy(f"./cvelistV5-main/cves/{by_year}/{folders}/{file}", "database")
                    else:
                        continue"""
                uic.loadUi("check_for_updates_new.ui", self)
                self.setWindowTitle("Наличие обновлений")
                self.setWindowIcon(QIcon("icon.ico"))
                self.btn_back.clicked.connect(self.menu)

            else:
                uic.loadUi("check_for_updates_new.ui", self)
                self.setWindowTitle("Наличие обновлений")
                self.setWindowIcon(QIcon("icon.ico"))
                self.btn_back.clicked.connect(self.menu)

        else:
            upd_message = QMessageBox()
            upd_message.setWindowTitle("Завершено")
            upd_message.setWindowIcon(QIcon("icon.ico"))
            upd_message.setText("Новых обновлений не обнаружено")
            upd_message.setIcon(QMessageBox.Warning)
            upd_message.addButton("ОК", QMessageBox.YesRole)
            upd_message.exec_()
            uic.loadUi("check_for_updates_new.ui", self)
            self.setWindowTitle("Наличие обновлений")
            self.setWindowIcon(QIcon("icon.ico"))
            self.btn_back.clicked.connect(self.menu)

    def run_btn_scan_net(self):
        # gets IP address
        # IP range of the network from 192.168.0.0 to 192.168.0.255
        """ip = socket.gethostbyname(socket.gethostname())

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

        # puts data in table
        self.table_db.setRowCount(len(hosts))
        self.table_db.setColumnCount(len(hosts) + 1)
        for i, (name, mac, address) in enumerate(hosts):
            item_name = QTableWidgetItem(name)
            item_mac = QTableWidgetItem(mac)
            item_adr = QTableWidgetItem(address)
            self.table_ad.setItem(i, 0, item_name)
            self.table_ad.setItem(i, 1, item_mac)
            self.table_ad.setItem(i, 2, item_adr)"""

    def run_btn_check_device(self):
        pass

    def run_btn_app_doc(self):
        w = uic.loadUi("docs.ui", self)
        self.setWindowTitle("Руководство по Эксплуатации")
        self.setWindowIcon(QIcon("icon.ico"))

        url_app_doc = "https://github.com/shersh-is/IoT-SecurityPoint/blob/main/docs/application_doc.md"
        self.browser = QWebEngineView()
        self.browser.load(QtCore.QUrl(url_app_doc))

        widget = QWidget()
        w.setCentralWidget(widget)
        lay = QVBoxLayout(widget)
        lay.addWidget(self.browser)

        lay.addWidget(self.btn_back)
        self.btn_back.clicked.connect(self.menu)

    def run_btn_tech_doc(self):
        w = uic.loadUi("docs.ui", self)
        self.setWindowTitle("Документация")
        self.setWindowIcon(QIcon("icon.ico"))

        url_app_doc = "https://github.com/shersh-is/IoT-SecurityPoint/blob/main/docs/technical_doc.md"
        self.browser = QWebEngineView()
        self.browser.load(QtCore.QUrl(url_app_doc))

        widget = QWidget()
        w.setCentralWidget(widget)
        lay = QVBoxLayout(widget)
        lay.addWidget(self.browser)

        lay.addWidget(self.btn_back)
        self.btn_back.clicked.connect(self.menu)


if __name__ == "__main__":
    main_date = ""
    app = QApplication(sys.argv)
    iot = Application()
    iot.show()
    sys.exit(app.exec())
