import json
from management.net.client import Client


class Agency(Client):
    def __init__(self, ip, port, file):
        Client.__init__(self, ip, port)
        self.file = file
        self.size = 8192

    def send_file(self):
        with open(self.file, 'rb') as f:
            while True:
                data = f.read(self.size)
                if not data:
                    break
                Client.send(self, data)

    def recv_results(self):
        data = Client.recv(self, self.size)
        return json.loads(data.decode())
