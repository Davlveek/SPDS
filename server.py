import socket


class Server:
    def __init__(self, ip, port):
        self.server_address = (ip, port)
        self.connection = None
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(self.server_address)
        except Exception as e:
            print(f'Socket not created\nException: {e}')

    def listen(self, backlog):
        try:
            self.sock.listen(backlog)
        except Exception as e:
            print(f'Listining failed\nException:{e}')

    def accept_connection(self):
        try:
            self.connection, addr = self.sock.accept()
            return addr
        except Exception as e:
            print(f'Connection accepting failed\nException: {e}')

    def send(self, data):
        pass

    def recv(self, size):
        pass

    def close(self):
        self.sock.close()