import json
from management.net.client import Client


class Agency(Client):
    def __init__(self, ip, port):
        Client.__init__(self, ip, port)
        self.size = 4096

    def send_file(self, file):
        with open(file, 'rb') as f:
            while True:
                data = f.read(self.size)
                if not data:
                    break
                Client.send(self, data)

    def recv_file(self, filename):
        with open(filename, 'wb') as f:
            while True:
                data = Client.recv(self, self.size)
                if not data:
                    break
                f.write(data)

    def recv_results(self):
        data = Client.recv(self, self.size)
        return json.loads(data.decode())
