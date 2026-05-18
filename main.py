import os
from RuleForApacheBruteforce import HttpBruteforce
from RuleForSshBruteforce import SshBruteforce
from RuleForDos import DOS
import threading
import sys


# Retrieve Elasticsearch connection details from environment
elasticsearch_host = os.environ.get('ELASTICSEARCH_HOST')
elasticsearch_port = os.environ.get('ELASTICSEARCH_PORT')
if not elasticsearch_host or not elasticsearch_port:
    raise EnvironmentError("ELASTICSEARCH_HOST and ELASTICSEARCH_PORT must be set")

elasticsearch_url = f"http://{elasticsearch_host}:{elasticsearch_port}"


while True:
    try:
        print("#######################################################")
        print("Connected to Elasticsearch")
        print("#######################################################")
        # Create an instance of HttpBruteforce
        http_engine = HttpBruteforce('rules.yaml', [elasticsearch_url])

        # Create a thread for HttpBruteforce and start it
        http_thread = threading.Thread(target=http_engine.process_apache_logs, args=('access_log',))
        http_thread.start()

        # Create an instance of SshBruteforce
        ssh_engine = SshBruteforce('rules.yaml', [elasticsearch_url])

        # Create a thread for SshBruteforce and start it
        ssh_thread = threading.Thread(target=ssh_engine.process_auth_logs, args=('test',))
        ssh_thread.start()

        # Create an instance of RuleEngine
        engine = DOS('rules.yaml', [elasticsearch_url])

        # Create a thread for DOS and start it
        dos_thread = threading.Thread(target=engine.process_kern_logs, args=('doslog',))
        dos_thread.start()

        # Wait for all threads to complete
        http_thread.join()
        ssh_thread.join()
        dos_thread.join()
    except KeyboardInterrupt:
        sys.exit()