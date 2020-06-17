from management.cuckoo.cuckoo_agency import CuckooAgency


def analysis(file):
    try:
        agency = CuckooAgency()

        vm = agency.config['vm']
        snapshot = agency.config['snapshot']
        agency.restore_snapshot(vm, snapshot)
        agency.power_on(vm)

        agency.connect()
        print(f'Connected to agent {agency.server_ip} port {agency.server_port}')

        agency.send_file(file)
        print('Sended file to agent')

        agency.recv_file('reports\\cuckoo.json')
        print('Received cuckoo report from agent')

        agency.close()
        agency.power_off(vm)
    except Exception as e:
        print(f'Exception: {e}')
