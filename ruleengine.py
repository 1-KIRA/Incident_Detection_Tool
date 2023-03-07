import yaml
from collections import defaultdict
import datetime
from ConnectAndQueryInElastic import ElasticsearchQuery
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

# Load YAML rule from file
with open('rules.yaml', 'r') as f:
    rule = yaml.safe_load(f)

# Initialize data structure to store failed login attempts
ip_attempts = defaultdict(int)
ip_last_attempt_time = {}

# Connect to Elasticsearch
es = ElasticsearchQuery()

# Define Elasticsearch query to retrieve log entries
query = Q('match', action='Failed password') & Q('exists', field='IPV4')
s = Search(using=es, index='test').query(query)

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
        ip_attempts[ip_address] += 1
        # Check if the IP address has reached the threshold in the specified timeframe
        if ip_attempts[ip_address] >= rule['conditions'][0]['count']:
            if ip_address in ip_last_attempt_time and \
               (timestamp - ip_last_attempt_time[ip_address]).seconds <= rule['conditions'][0]['timeframe']:
                print(f"Incident detected: {ip_address} made {ip_attempts[ip_address]} failed login attempts within {rule['conditions'][0]['timeframe']} seconds in {hostname} for user {user}.")
                # Clear the number of attempts for this IP
                ip_attempts[ip_address] = 0
            else:
                # Update last attempted time for the IP
                ip_last_attempt_time[ip_address] = timestamp
                ip_attempts[ip_address] = 1
