import yaml
from elasticsearch import Elasticsearch

# Load the rules from the YAML file
with open('rules.yaml') as f:
    rules = yaml.load(f, Loader=yaml.FullLoader)['rules']

# Connect to Elasticsearch
es =  Elasticsearch(['http://3.229.13.155:9200'])

# Define a function to check if a log matches a rule
def check_rule(log, rule):
    for condition in rule['conditions']:
        if condition['when']['field'] in log and condition['when']['contains'] in log[condition['when']['field']]:
            return True
    return False

# Define a function to process a matched rule
def process_rule(rule):
    for action in rule['actions']:
        if 'log' in action:
            print(action['log'])
        if 'file' in action:
            with open(action['file'], 'a') as f:
                f.write(f'{rule["name"]}: {log}\n')

# Query Elasticsearch for logs and check for incidents
query = {'query': {'match_all': {}}}
search_result = es.search(index='parsed_auth_log', body=query, size=1000)
for hit in search_result['hits']['hits']:
    log = hit['_source']
    for rule in rules:
        if check_rule(log, rule):
            process_rule(rule)
