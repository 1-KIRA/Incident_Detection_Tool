import yaml
import datetime
from elasticsearch import Elasticsearch, exceptions
from elasticsearch_dsl import Search, Q
from smtp import GmailSender
import sys
import os


class DOS:
    def __init__(self, rules_file_path, elasticsearch_hosts, http_auth=None, use_ssl=True, verify_certs=True, ca_certs=None):
        # Load YAML rule from file
        with open(rules_file_path, 'r') as f:
            self.rule = yaml.safe_load(f)

        # Enforce HTTPS for all hosts
        secure_hosts = []
        for host in elasticsearch_hosts:
            if host.startswith('http://'):
                # Convert to https and warn (or simply replace)
                secure_host = host.replace('http://', 'https://', 1)
                print(f"Warning: Host {host} uses insecure HTTP; converting to {secure_host}")
                secure_hosts.append(secure_host)
            elif not host.startswith('https://'):
                # Assume missing scheme; prepend https
                secure_host = 'https://' + host
                print(f"Warning: Host {host} missing scheme; assuming {secure_host}")
                secure_hosts.append(secure_host)
            else:
                secure_hosts.append(host)

        # If http_auth not provided, try to read from environment variables
        if http_auth is None:
            user = os.environ.get('ES_USER')
            password = os.environ.get('ES_PASS')
            if user and password:
                http_auth = (user, password)
            else:
                # For security, require authentication; raise error if missing
                raise ValueError("Elasticsearch authentication credentials are required. Set ES_USER and ES_PASS environment variables or pass http_auth.")

        # Connect to Elasticsearch with TLS/SSL and authentication
        self.es = Elasticsearch(
            secure_hosts,
            http_auth=http_auth,
            use_ssl=use_ssl,
            verify_certs=verify_certs,
            ca_certs=ca_certs
        )

    def process_kern_logs(self, index_name):
        today = datetime.datetime.now().date()
        query = Q('exists', field='Data')
        s = Search(using=self.es, index=index_name).query(query)

        # Process log entries
        try:
            for hit in s.scan():
                # Extract relevant fields (e.g., IP address, timestamp)
                message = hit.Data
                port=hit.port
                host=hit.Hostname
                outTimestamp=hit.Timestamp
                timestamp = datetime.datetime.fromisoformat(hit['@timestamp'][:-1]).strftime("%Y-%m-%d")
                time=datetime.datetime.now().strftime("%Y-%m-%d")
                
                if str(timestamp)==str(time):

                    if message == self.rule['conditions'][2]['contains'] or self.rule['conditions'][2]['contain']:
                    # Check if failed login attempt matches the rule
                        alert=(f"Incident detected: {message} on port {port} in host: {host} on {outTimestamp}")
                        # Clear the number of attempts for this IP
                        sender = GmailSender('env.txt')
                        sender.send_email('Incident Detected', alert)
                        now = datetime.datetime.now()
                        formatted_date = now.strftime("%Y-%m-%d %H:%M:%S")
                        send_log_index='myindex'
                        detected_incident={'Timestamp':formatted_date,'Hostname': host,'Message':alert,'Port':port}
                        self.es.index(index=send_log_index, document=detected_incident)
                        break
                        
        except AttributeError:
            print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print('The field you entered doesnot exist ')
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
        except exceptions.ConnectionError:
            print()
        except KeyboardInterrupt:
            sys.exit()

# try:
#     while True:               
#         # Create an instance of RuleEngine with secure Elasticsearch connection
#         # (use HTTPS and authentication – set ES_USER/ES_PASS environment variables)
#         engine = DOS('rules.yaml', ['https://3.229.13.155:9200'])

#         # Call the process_logs method to run the rule engine
#         engine.process_kern_logs('doslog')

# except exceptions.ConnectionError:
#      print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
#      print('Elascticsearch not connected. Elasticsearch seems down \n')
#      print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
#      sys.exit()