import json
from management.dynamorio.dynamorio_agency import DynamoRioAgency


def analysis(file):
    try:
        agency = DynamoRioAgency(file)

        vm = agency.config['vm']
        snapshot = agency.config['snapshot']
        agency.restore_snapshot(vm, snapshot)
        agency.power_on(vm)

        agency.connect()
        print(f'Connected to agent {agency.server_ip} port {agency.server_port}')

        agency.send_file(agency.file)
        print('Sended file to agent')

        tricks = agency.recv_results()
        print('Received dynamorio results from agent')
        with open('dynamorio.json', 'w') as f:
            json.dump(tricks, f, sort_keys=False, indent=4)

        agency.close()
        agency.power_off(vm)
    except Exception as e:
        print(f'Exception: {e}')


if __name__ == '__main__':
    analysis('file')
