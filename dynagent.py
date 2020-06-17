from management.dynamorio.dynamorio_agent import DynamoRioAgent


if __name__ == '__main__':
    try:
        agent = DynamoRioAgent()
        agent.listen(1)
        agent.accept_connection()

        agent.recv_file(agent.file)
        print('File received from agency')

        agent.start_dynamorio_analysis()
        print('DynamoRIO analysis finished')

        t = agent.form_dict_results()
        print('Results parsing finished')

        agent.send_results(t)
        print('Results sended to agency')

        agent.close_connection()
        agent.close_socket()
    except Exception as e:
        print(f'Exception: {e}')
