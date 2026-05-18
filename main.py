import os
import sys
import threading
from RuleForApacheBruteforce import HttpBruteforce
from RuleForSshBruteforce import SshBruteforce
from RuleForDos import DOS

# Retrieve Elasticsearch endpoints from environment variable.
# Expected format: comma‑separated list of URLs, e.g. "http://es1:9200,http://es2:9200"
_elasticsearch_endpoints = os.getenv("ELASTICSEARCH_ENDPOINTS")
if not _elasticsearch_endpoints:
    sys.stderr.write(
        "Error: ELASTICSEARCH_ENDPOINTS environment variable not set.\n"
    )
    sys.exit(1)

# Convert the comma‑separated string into a list of endpoints.
_elasticsearch_hosts = [host.strip() for host in _elasticsearch_endpoints.split(",") if host.strip()]

while True:
    try:
        print("#######################################################")
        print("Connected to Elasticsearch")
        print("#######################################################")

        # Create an instance of HttpBruteforce
        http_engine = HttpBruteforce('rules.yaml', _elasticsearch_hosts)

        # Create a thread for HttpBruteforce and start it
        http_thread = threading.Thread(
            target=http_engine.process_apache_logs,
            args=('access_log',)
        )
        http_thread.start()

        # Create an instance of SshBruteforce
        ssh_engine = SshBruteforce('rules.yaml', _elasticsearch_hosts)

        # Create a thread for SshBruteforce and start it
        ssh_thread = threading.Thread(
            target=ssh_engine.process_auth_logs,
            args=('test',)
        )
        ssh_thread.start()

        # Create an instance of RuleEngine
        engine = DOS('rules.yaml', _elasticsearch_hosts)

        # Create a thread for DOS and start it
        dos_thread = threading.Thread(
            target=engine.process_kern_logs,
            args=('doslog',)
        )
        dos_thread.start()

        # Wait for all threads to complete
        http_thread.join()
        ssh_thread.join()
        dos_thread.join()
    except KeyboardInterrupt:
        sys.exit()