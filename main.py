from RuleForApacheBruteforce import HttpBruteforce
from RuleForSshBruteforce import SshBruteforce
from RuleForDos import DOS
from elasticsearch import exceptions
from multiprocessing import Process
import sys

if exceptions.ConnectionError:
    print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
    print('Elascticsearch not connected. Elasticsearch seems down. \n')
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
    sys.exit()

else:
    try:
        # Define functions to run the engine processes
        def run_http_engine():
            HttpEngine = HttpBruteforce('rules.yaml', ['http://3.229.13.155:9200'])
            while True:
                HttpEngine.process_apache_logs('access_log')
                print('HTTP engine running...')

        def run_ssh_engine():
            SshEngine = SshBruteforce('rules.yaml', ['http://3.229.13.155:9200'])
            while True:
                SshEngine.process_auth_logs('test')
                print('SSH engine running...')

        def run_dos_engine():
            DosEngine = DOS('rules.yaml', ['http://3.229.13.155:9200'])
            while True:
                DosEngine.process_kern_logs('doslog')
                print('DOS engine running...')


        if __name__ == '__main__':
            # Create separate processes for each engine
            http_process = Process(target=run_http_engine)
            ssh_process = Process(target=run_ssh_engine)
            dos_process = Process(target=run_dos_engine)
            
            # Start the processes
            http_process.start()
            ssh_process.start()
            dos_process.start()

            # Wait for the processes to finish
            http_process.join()
            ssh_process.join()
            dos_process.join()
    except KeyboardInterrupt:
        sys.exit()