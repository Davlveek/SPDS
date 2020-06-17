import time
from management.cuckoo.cuckoo_agent import CuckooAgent

if __name__ == '__main__':
    try:
        agent = CuckooAgent()
        agent.listen(1)
        agent.accept_connection()

        agent.recv_file(agent.file)
        print('File received from agency')

        agent.start_cuckoo_analysis()
        agent.check_analysis_end()
        print('Cuckoo analysis ended')

        agent.send_cuckoo_report()
        print('Sended cuckoo report')

        time.sleep(180)

        agent.close_connection()
        agent.close_socket()
    except Exception as e:
        print(f'Exception: {e}')
