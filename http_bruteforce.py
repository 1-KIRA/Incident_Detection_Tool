import yaml
from collections import defaultdict
import datetime
from elasticsearch import Elasticsearch, exceptions
from elasticsearch_dsl import Search, Q
from smtp import GmailSender
class HttpBruteforce:
    def __init__(self, rules_file_path, elasticsearch_hosts):
    # Load YAML rule from file
        with open(rules_file_path, 'r') as f:
            self.rule = yaml.safe_load(f)
        # Initialize data structure to store failed login attempts
        self.ip_attempts = defaultdict(int)
        self.http_url_attempts= defaultdict(int)
        self.ip_last_attempt_time = {}


        # Connect to Elasticsearch
        self.es = Elasticsearch(elasticsearch_hosts)

    def process_logs(self, index_name):
        query = Q('exists', field='username_pass'),
        s = Search(using=self.es, index=index_name).query(query)

        # Process log entries
        for hit in s.scan():
            # Extract relevant fields (e.g., IP address, timestamp)
            http_ip_address = hit.client
            timestamp = datetime.datetime.strptime(hit['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
            http_url=hit.url
            # Check if failed login attempt matches the rule
            if http_ip_address and http_url:
                # Update data structure with new failed login attempt
                self.ip_attempts[http_ip_address] += 1
                self.http_url_attempts[http_url] +=1

                # Check if the IP address has reached the threshold in the specified timeframe
                if self.ip_attempts[http_ip_address] >= self.rule['conditions'][1]['http_count']:
                    if http_ip_address in self.ip_last_attempt_time and \
                    (timestamp - self.ip_last_attempt_time[http_ip_address]).seconds <= self.rule['conditions'][1]['http_timeframe']:
                        alert=(f"Incident detected: {http_ip_address} made {self.ip_attempts[http_ip_address]} failed login attempts within {self.rule['conditions'][1]['http_timeframe']} seconds in {http_url}")
                        # Clear the number of attempts for this IP
                        self.ip_attempts[http_ip_address] = 0
                        sender = GmailSender('env.txt')
                        sender.send_email('Incident Detected', alert)
                        now = datetime.datetime.now()
                        formatted_date = now.strftime("%Y-%m-%d %H:%M:%S")
                        send_log_index='myindex'
                        detected_incident={'Timestamp':formatted_date,'IPV4':http_ip_address,'Message':alert,'URL':http_url}
                        self.es.index(index=send_log_index, body=detected_incident)
                        break
                    else:
                        # Update last attempted time for the IP
                        self.ip_last_attempt_time[http_ip_address] = timestamp
                        self.ip_attempts[http_ip_address] = 1
try:                    
    # Create an instance of RuleEnginea
    engine = HttpBruteforce('rules.yaml', ['http://3.229.13.155:9200'])

    # Call the process_logs method to run the rule engine
    engine.process_logs('access_log')
except exceptions.ConnectionError:
     print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
     print('Elascticsearch not connected. Elasticsearch seems down \n')
     print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
     sys.exit()