import re
import socket


class Whois:
    _HOST = "whois.ripe.net"
    _PORT = 43

    def __init__(self, ip):
        self.ip = ip
        self.buf = ""
        self.county_regex = re.compile(r"country:[ ]*(\w*)\n")
        self.name_AS_regex = re.compile(r"(?:origin|OriginAS):[ ]*(.*)\n")
        self.net_name_regex = re.compile(r"[nN]et[Nn]ame:[ ]*(.*)\n")
        self.name_AS = ""
        self.country = ""
        self.netname = ""

    def create(self):
        s = socket.create_connection((self._HOST, self._PORT))
        s.sendall(f'{self.ip}\r\n'.encode())
        while True:
            buf = s.recv(1024).decode("utf-8")
            self.buf += buf
            if len(buf) == 0:
                break

    def parse(self):
        try:
            self.country = self.county_regex.findall(self.buf)[0]
        except IndexError:
            self.country = ""
        try:
            self.netname = self.net_name_regex.findall(self.buf)[0]
        except IndexError:
            self.netname = ""
        try:
            self.name_AS = self.name_AS_regex.findall(self.buf)[0]
        except IndexError:
            self.name_AS = ""

    def get_result(self):
        self.create()
        self.parse()
        return self.name_AS, self.country, self.netname
