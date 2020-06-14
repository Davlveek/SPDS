import json
import os
import time
from management.net.agent import Agent


class CuckooAgent(Agent):
    file = 'file.exe'
    end_msg = 'analysis procedure completed'

    def __init__(self):
        with open('management/config.json', 'r') as f:
            self.config = json.load(f)['cuckoo']
        Agent.__init__(self, self.config['address'], self.config['port'])

    def start_cuckoo_analysis(self):
        os.system(f'sudo cuckoo submit {self.file}')

    def check_analysis_end(self):
        with open(self.config['log_path'], 'r') as log_file:
            last_line = log_file.readlines()[-1]

            cnt = 0
            while True:
                time.sleep(60)
                cnt += 1
                if last_line.find(self.end_msg):
                    return True
                elif cnt == 10:
                    return False

    def send_cuckoo_report(self):
        Agent.send_file(self, self.config['report_path'])
