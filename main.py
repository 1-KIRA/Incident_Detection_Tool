from RuleForApacheBruteforce import HttpBruteforce
from RuleForSshBruteforce import SshBruteforce
from RuleForDos import DOS
import threading
import sys
from elasticsearch import exceptions

while True:
    try:
        # Create an instance of HttpBruteforce
        http_engine = HttpBruteforce('rules.yaml', ['http://3.229.13.155:9200'])

        # Create a thread for HttpBruteforce and start it
        http_thread = threading.Thread(target=http_engine.process_apache_logs, args=('access_log',))
        print("HTTP")
        http_thread.start()
    except exceptions.ConnectionError:
        print("Not connected to ES")
        # Create an instance of SshBruteforce
    try:
        ssh_engine = SshBruteforce('rules.yaml', ['http://3.229.13.155:9200'])

        # Create a thread for SshBruteforce and start it
        ssh_thread = threading.Thread(target=ssh_engine.process_auth_logs, args=('test',))
        print("SSH")
        ssh_thread.start()
    except exceptions.ConnectionError:
        print("Not connected to ES")
        # Create an instance of RuleEngine
    try:
        engine = DOS('rules.yaml', ['http://3.229.13.155:9200'])
        # Create a thread for DOS and start it
        dos_thread = threading.Thread(target=engine.process_kern_logs, args=('doslog',))
        print("DOS")
        dos_thread.start()

    except exceptions.ConnectionError:
        print("Not connected to ES")

    try:
        # Wait for all threads to complete
        http_thread.join()
        ssh_thread.join()
        dos_thread.join()
    except exceptions.ConnectionError:
        sys.exit()

