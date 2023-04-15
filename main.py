from RuleForApacheBruteforce import HttpBruteforce
from RuleForSshBruteforce import SshBruteforce
from RuleForDos import DOS
import threading
from elasticsearch import exceptions
import sys


while True:
    try:
        # Create an instance of HttpBruteforce
        http_engine = HttpBruteforce('rules.yaml', ['http://3.229.13.155:9200'])

        # Create a thread for HttpBruteforce and start it
        http_thread = threading.Thread(target=http_engine.process_apache_logs, args=('access_log',))
        http_thread.start()

        # Create an instance of SshBruteforce
        ssh_engine = SshBruteforce('rules.yaml', ['http://3.229.13.155:9200'])

        # Create a thread for SshBruteforce and start it
        ssh_thread = threading.Thread(target=ssh_engine.process_auth_logs, args=('test',))
        ssh_thread.start()

        # Create an instance of RuleEngine
        engine = DOS('rules.yaml', ['http://3.229.13.155:9200'])

        # Create a thread for DOS and start it
        dos_thread = threading.Thread(target=engine.process_kern_logs, args=('doslog',))
        dos_thread.start()

        # Wait for all threads to complete
        http_thread.join()
        ssh_thread.join()
        dos_thread.join()
    except KeyboardInterrupt:
        sys.exit()
