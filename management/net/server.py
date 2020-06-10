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
            print(f'Server listining on {self.server_address[0]} port {self.server_address[1]}')
        except Exception as e:
            print(f'Listining failed\nException:{e}')

    def accept_connection(self):
        try:
            self.connection, addr = self.sock.accept()
            print(f'Accepted connection: {addr}')
            return addr
        except Exception as e:
            print(f'Connection accepting failed\nException: {e}')

    def send(self, data):
        self.connection.send(data)

    def recv(self, size):
        return self.connection.recv(size)

    def close_connection(self):
        self.connection.close()

    def close_socket(self):
        self.sock.close()
