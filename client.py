import socket


class Client:
    def __init_(self, ip: object, port: object):
        self.server_ip = ip
        self.server_port = port
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as e:
            print(f'Socket not created\nException:{e}')

    def connect(self):
        try:
            self.sock.connect((self.server_ip, self.server_port))
        except Exception as e:
            print(f'Connection to server({self.server_ip} failed\nException:{e})')

    def send(self, data):
        pass

    def recv(self, size):
        pass

    def close(self):
        try:
            self.sock.close()
        except Exception as e:
            print(f'Closing socket failed\nException: {e}')
