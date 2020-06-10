import json
from management.net.agency import Agency
from management.virtualbox import VirtualBox


class DynamoRioAgency(Agency, VirtualBox):
    def __init__(self, file):
        with open('management\\config.json', 'r') as f:
            self.config = json.load(f)['dynamorio']
        Agency.__init__(self, self.config['address'], self.config['port'], file)
