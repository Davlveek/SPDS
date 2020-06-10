import json
from management.net.server import Server


class Agent(Server):
    def __init__(self, ip, port):
        Server.__init__(self, ip, port)
        self.size = 8192

    def recv_file(self, filename):
        with open(filename, 'wb') as f:
            while True:
                data = Server.recv(self, self.size)
                if not data:
                    break
                f.write(data)

    def send_results(self, tricks):
        data = str.encode(json.dumps(tricks))
        Server.send(self, data)
