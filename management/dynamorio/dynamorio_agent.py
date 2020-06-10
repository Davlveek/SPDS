import json
import os
from management.net.agent import Agent


class DynamoRioAgent(Agent):
    file = 'file.exe'

    def __init__(self):
        with open('management\\config.json', 'r') as f:
            self.config = json.load(f)['dynamorio']
        Agent.__init__(self, self.config['address'], self.config['port'])

    def start_dynamorio_analysis(self):
        client = self.config['client']
        os.system(f'bin32\\drrun.exe -c {client} -- {self.file}')

    def form_dict_results(self):
        tricks = {}

        filename = self.file.replace('.exe', '')
        with open(f'{filename}[AntiDebug].txt', 'r') as file:
            for line in file:
                splits = line.split(' ')
                tricks[splits[0]] = False if splits[1] == '[GOOD]\n' else True

        return tricks
