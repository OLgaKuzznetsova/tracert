import os
import re
import socket

from whois import Whois


class Tracert:
    def __init__(self, ip):
        self.ip = ip
        self.ip_regex = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        self.all_ip = []
        self.get_ip()

    def get_ip(self):
        tracert = os.popen(f"tracert {self.ip}")
        line = tracert.readline()
        while line:
            line = tracert.readline()
            if "ms" in line:
                try:
                    ip = self.ip_regex.findall(line)[0]
                    self.all_ip.append(ip)
                except:
                    self.all_ip.append("*")
            elif "*" in line:
                self.all_ip.append("*")
        if len(self.all_ip) == 0:
            print("Не удается разрешить системное имя узла " + self.ip)
        else:
            self.get_data_from_whois()

    def get_data_from_whois(self):
        for i in range(len(self.all_ip)):
            if self.all_ip[i] == self.get_local_ip():
                self.print_result(i+1, self.all_ip[i], "local", "", "")
            elif self.is_grey_ip(self.all_ip[i]):
                self.print_result(i+1, self.all_ip[i], "", "", "")
            elif self.all_ip[i] == "*":
                self.print_result(i+1, "*", "", "", "")
            else:
                name_AS, country, netname = Whois(self.all_ip[i]).get_result()
                self.print_result(i+1, self.all_ip[i], netname, name_AS, country)

    @staticmethod
    def print_result(number, ip, netname, as_name, country):
        if netname != "":
            if as_name != "":
                netname = netname + ","
                if country != "":
                    as_name = as_name + ","
            else:
                if country != "":
                    netname = netname + ","
        else:
            if as_name != "" and country != "":
                as_name = as_name + ","
        if ip == "*":
            print(f"{number}. {ip}\r\n"
                  f"\r\n")
        else:
            print(f"{number}. {ip}\r\n"
                  f"{netname} {as_name} {country}\r\n"
                  f"\r\n")

    @staticmethod
    def is_grey_ip(ip):
        return ip.startswith('192.168.') \
               or ip.startswith('10.') \
               or (ip.startswith('172.')
                   and 15 < int(ip.split('.')[1]) < 32)

    @staticmethod
    def get_local_ip():
        return socket.gethostbyname(socket.gethostname())
