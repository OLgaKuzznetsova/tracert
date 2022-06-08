import re
from urllib.request import urlopen, Request


class Whois:
    def __init__(self, ip):
        self.ip = ip
        self.data = ""
        self.county_regex = re.compile(r"[Cc]ountry: *(\w*)\r\n")
        self.name_AS_regex = re.compile(r"(?:origin|OriginAS):[ ]*(.*)\r\n")
        self.net_name_regex = re.compile(r"[nN]et[Nn]ame:[ ]*(.*)\r\n")
        self.name_AS = ""
        self.country = ""
        self.netname = ""

    def create(self):
        try:
            url = f"https://whois.ru/{self.ip}"
            req = Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            self.data = urlopen(req).read().decode()
        except:
            pass

    def parse(self):
        try:
            self.country = self.county_regex.findall(self.data)[0]
        except IndexError:
            self.country = ""
        try:
            self.netname = self.net_name_regex.findall(self.data)[0]
        except IndexError:
            self.netname = ""
        try:
            self.name_AS = self.name_AS_regex.findall(self.data)[0]
        except IndexError:
            self.name_AS = ""

    def get_result(self):
        self.create()
        self.parse()
        return self.name_AS, self.country, self.netname
