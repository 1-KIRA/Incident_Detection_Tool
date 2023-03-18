import yaml
from collections import defaultdict
import datetime
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q


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
        
    def process_logs(self, index_name):
        # Elasticsearch query to retrieve log entries
        query = Q('match', action='Failed password for') & Q('exists', field='IPV4')
        s = Search(using=self.es, index=index_name).query(query)

        # Process log entries
        for hit in s.scan():
            # Extract relevant fields (e.g., IP address, timestamp)
            ip_address = hit.IPV4
            timestamp = datetime.datetime.strptime(hit['Timestamp'], '%b %d %H:%M:%S')
            hostname=hit.hostname
            user=hit.User
            # Check if failed login attempt matches the rule
            if ip_address:
                # Update data structure with new failed login attempt
                self.ip_attempts[ip_address] += 1
                # Check if the IP address has reached the threshold in the specified timeframe
                if self.ip_attempts[ip_address] >= self.rule['conditions'][0]['count']:
                    if ip_address in self.ip_last_attempt_time and \
                       (timestamp - self.ip_last_attempt_time[ip_address]).seconds <= self.rule['conditions'][0]['timeframe']:
                        print(f"Incident detected: {ip_address} made {self.ip_attempts[ip_address]} failed login attempts within {self.rule['conditions'][0]['timeframe']} seconds in {hostname} for user {user}.")
                        # Clear the number of attempts for this IP
                        self.ip_attempts[ip_address] = 0
                    else:
                        # Update last attempted time for the IP
                        self.ip_last_attempt_time[ip_address] = timestamp
                        self.ip_attempts[ip_address] = 1

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
            sd
        query = Q('exists', field='username_pass')
        s = Search(using=self.es, index=index_name).query(query)

        # Process log entries
        for hit in s.scan():
            # Extract relevant fields (e.g., IP address, timestamp)
            http_ip_address = hit.client
            timestamp = datetime.datetime.strptime(hit['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
            httpstatus=hit.http_status
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
                        print(f"Incident detected: {http_ip_address} made {self.ip_attempts[http_ip_address]} failed login attempts within {self.rule['conditions'][1]['http_timeframe']} seconds in {http_url}.")
                        # Clear the number of attempts for this IP
                        self.ip_attempts[http_ip_address] = 0
                        
                        break
                    else:
                        # Update last attempted time for the IP
                        self.ip_last_attempt_time[http_ip_address] = timestamp
                        self.ip_attempts[http_ip_address] = 1
                    
    # Create an instance of RuleEnginea
engine = HttpBruteforce('rules.yaml', ['http://3.229.13.155:9200'])

# Call the process_logs method to run the rule engine
engine.process_logs('access_log')
