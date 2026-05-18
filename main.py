from RuleForApacheBruteforce import HttpBruteforce
from RuleForSshBruteforce import SshBruteforce
from RuleForDos import DOS
import threading
import sys
import re
import os

# Security validation helper for index names to prevent injection
def validate_index_name(index_name):
    if not re.match(r'^[a-zA-Z0-9_\-]+$', index_name):
        raise ValueError(f"Invalid index name: {index_name}. Only alphanumeric, underscore, and hyphen allowed.")

while True:
    try:
        print("#######################################################")
        print("Connected to Elasticsearch")
        print("#######################################################")

        # Fetch Elasticsearch URL from environment variable (secure) with fallback
        es_urls = os.environ.get('ELASTICSEARCH_URLS', 'http://3.229.13.155:9200').split(',')

        # Validate all URLs are HTTPS or local (optional; here only basic check)
        for url in es_urls:
            if not url.startswith('http://') and not url.startswith('https://'):
                raise ValueError(f"Invalid Elasticsearch URL: {url}")

        # Define allowed index names as constants (no user entry directly)
        APACHE_INDEX = 'access_log'
        SSH_INDEX = 'test'
        DOS_INDEX = 'doslog'

        # Validate index names (defense in depth)
        validate_index_name(APACHE_INDEX)
        validate_index_name(SSH_INDEX)
        validate_index_name(DOS_INDEX)

        # Create instances with validated inputs
        http_engine = HttpBruteforce('rules.yaml', es_urls)
        ssh_engine = SshBruteforce('rules.yaml', es_urls)
        engine = DOS('rules.yaml', es_urls)

        # Create and start threads
        http_thread = threading.Thread(target=http_engine.process_apache_logs, args=(APACHE_INDEX,))
        http_thread.start()

        ssh_thread = threading.Thread(target=ssh_engine.process_auth_logs, args=(SSH_INDEX,))
        ssh_thread.start()

        dos_thread = threading.Thread(target=engine.process_kern_logs, args=(DOS_INDEX,))
        dos_thread.start()

        # Wait for all threads to complete
        http_thread.join()
        ssh_thread.join()
        dos_thread.join()
    except KeyboardInterrupt:
        sys.exit()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)