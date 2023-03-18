import yaml
from collections import defaultdict
import datetime
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

# Load YAML rule from file
with open('rules.yaml', 'r') as f:
    rule = yaml.safe_load(f)

# Initialize data structure to store failed login attempts
ip_attempts = defaultdict(int)
http_url_attempts= defaultdict(int)
http_ip_last_attempt_time = {}

# Connect to Elasticsearch
es = Elasticsearch(['http://3.229.13.155:9200'])

# Define Elasticsearch query to retrieve log entries
query = Q('exists', field='username_pass')
s = Search(using=es, index='access_log').query(query)

# Process log entries
for hit in s.scan():
    # Extract relevant fields (e.g., IP address, timestamp)
    http_ip_address = hit.client
    timestamp = datetime.datetime.strptime(hit['timestamp'], '%d/%b/%Y:%H:%M:%S %z')
    httpstatus=hit.http_status
    http_url=hit.url


    print(http_ip_last_attempt_time)
    # Check if failed login attempt matches the rule
    if http_ip_address and http_url:
        # Update data structure with new failed login attempt
        ip_attempts[http_ip_address] += 1
        http_url_attempts[http_url] +=1

        # Check if the IP address has reached the threshold in the specified timeframe
        if ip_attempts[http_ip_address] >= rule['conditions'][1]['http_count']:
            if http_ip_address in http_ip_last_attempt_time and \
               (timestamp - http_ip_last_attempt_time[http_ip_address]).seconds < rule['conditions'][1]['http_timeframe']:
                print(f"Incident detected: {http_ip_address} made {ip_attempts[http_ip_address]} failed login attempts within {rule['conditions'][1]['http_timeframe']} seconds in {http_url}.")
                # Clear the number of attempts for this IP
                ip_attempts[http_ip_address] = 0
                break
            else:
                # Update last attempted time for the IP
                http_ip_last_attempt_time[http_ip_address] = timestamp
                ip_attempts[http_ip_address] = 1
