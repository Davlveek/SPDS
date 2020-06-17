import json
from management.net.agency import Agency
from management.virtualbox import VirtualBox


class CuckooAgency(Agency, VirtualBox):
    def __init__(self):
        with open('management\\config.json', 'r') as f:
            self.config = json.load(f)['cuckoo']
        Agency.__init__(self, self.config['address'], self.config['port'])
        VirtualBox.__init__(self)
