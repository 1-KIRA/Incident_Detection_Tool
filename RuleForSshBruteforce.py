import yaml
from collections import defaultdict
import datetime
from elasticsearch import Elasticsearch, exceptions
from elasticsearch_dsl import Search, Q
from smtp import GmailSender
import sys


class SshBruteforce:
    def __init__(self, rules_file_path, elasticsearch_hosts):
        # Load YAML rule from file
        with open(rules_file_path, 'r') as f:
            self.rule = yaml.safe_load(f)
        
        # Initialize data structure to store failed login attempts
        self.ip_attempts = defaultdict(int)
        self.ip_last_attempt_time = {}
        
        # Connect to Elasticsearch
        self.es = Elasticsearch(elasticsearch_hosts)
        
    def process_auth_logs(self, index_name):
        # Elasticsearch query to retrieve log entries
        query = Q('match', action='Failed password for') & Q('exists', field='IPV4')
        s = Search(using=self.es, index=index_name).query(query)

        # Process log entries
        try:
            for hit in s.scan():
                # Extract relevant fields (e.g., IP address, timestamp)
                ip_address = hit.IPV4
                outTimestamp=hit.Timestamp
                timestamp = datetime.datetime.strptime(hit['Timestamp'], '%b %d %H:%M:%S')
                hostname=hit.hostname
                user=hit.User
                Timestamp = datetime.datetime.fromisoformat(hit['@timestamp'][:-1]).strftime("%Y-%m-%d")
                time=datetime.datetime.now().strftime("%Y-%m-%d")
                
                # Check if failed login attempt matches the rule
                # if str(time)==str(Timestamp):
                if ip_address:
                    # Update data structure with new failed login attempt
                    self.ip_attempts[ip_address] += 1
                    # Check if the IP address has reached the threshold in the specified timeframe
                    if self.ip_attempts[ip_address] >= self.rule['conditions'][0]['count']:
                        if ip_address in self.ip_last_attempt_time and \
                        (timestamp - self.ip_last_attempt_time[ip_address]).seconds <= self.rule['conditions'][0]['timeframe'] :
                            alert=(f"Incident detected: {ip_address} made {self.ip_attempts[ip_address]} failed login attempts within {self.rule['conditions'][0]['timeframe']} seconds in {hostname} for user {user} in {time}")
                            sender = GmailSender('env.txt')
                            sender.send_email('Incident Detected', alert)
                            now = datetime.datetime.now()
                            formatted_date = now.strftime("%Y-%m-%d %H:%M:%S")
                            send_log_index='myindex'
                            detected_incident={'Timestamp':formatted_date,'IPV4':ip_address,"Hostname":hostname,'Message':alert,'Username':user}
                            self.es.index(index=send_log_index, document=detected_incident)
                            break
                        else:
                            # Update last attempted time for the IP
                            self.ip_last_attempt_time[ip_address] = timestamp
                            self.ip_attempts[ip_address] = 1
        except AttributeError:
            print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print('The field you entered doesnot exist. ')
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")

try:
    while True:
        engine = SshBruteforce('rules.yaml', ['http://3.229.13.155:9200'])

        # Call the process_logs method to run the rule engine
        engine.process_auth_logs('test')
        pass
except exceptions.ConnectionError:
     print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
     print('Elascticsearch not connected. Elasticsearch seems down \n')
     print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
     sys.exit()
except KeyboardInterrupt:
    sys.exit()