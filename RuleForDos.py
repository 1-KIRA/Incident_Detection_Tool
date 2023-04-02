import yaml
from datetime import datetime
from elasticsearch import Elasticsearch, exceptions
from elasticsearch_dsl import Search, Q
from smtp import GmailSender
import sys

class DOS:
    def __init__(self, rules_file_path, elasticsearch_hosts):
    # Load YAML rule from file
        with open(rules_file_path, 'r') as f:
            self.rule = yaml.safe_load(f)
       # Connect to Elasticsearch
        self.es = Elasticsearch(elasticsearch_hosts)
        
    def process_logs(self, index_name):
        today = datetime.now().date()
        query = Q('exists', field='Data') and Q('match', Timestamp=str(today))
        s = Search(using=self.es, index=index_name).query(query)

        # Process log entries
        for hit in s.scan():
            # Extract relevant fields (e.g., IP address, timestamp)
            message = hit.Data
            port=hit.port
            host=hit.Hostname

            if message == self.rule['conditions'][2]['contains'] or self.rule['conditions'][2]['contain']:
            # Check if failed login attempt matches the rule
                    alert=(f"Incident detected: {message} on port {port} in host: {host}")
                    # Clear the number of attempts for this IP
                    sender = GmailSender('env.txt')
                    sender.send_email('Incident Detected', alert)
                    now = datetime.datetime.now()
                    formatted_date = now.strftime("%Y-%m-%d %H:%M:%S")
                    send_log_index='myindex'
                    detected_incident={'Timestamp':formatted_date,'Hostname': host,'Message':alert,'Port':port}
                    self.es.index(index=send_log_index, document=detected_incident)
                    break
try:
    while True:               
        # Create an instance of RuleEngine
        engine = DOS('rules.yaml', ['http://3.229.13.155:9200'])

        # Call the process_logs method to run the rule engine
        engine.process_logs('dos_log')

except exceptions.ConnectionError:
     print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
     print('Elascticsearch not connected. Elasticsearch seems down \n')
     print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
     sys.exit()
     