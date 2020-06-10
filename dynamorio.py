import json
from management.dynamorio.dynamorio_agency import DynamoRioAgency


def analysis(file):
    try:
        agency = DynamoRioAgency(file)
        agency.connect()
        agency.send_file()
        tricks = agency.recv_results()
        with open('file1.txt', 'w') as f:
            json.dump(tricks, f, sort_keys=False, indent=4)
        agency.close()
    except Exception as e:
        print(f'Exception: {e}')


if __name__ == '__main__':
    analysis('file')
