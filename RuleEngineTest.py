import yaml
import re
from ConnectAndQueryInElastic import ElasticsearchQuery
es_query = ElasticsearchQuery()

class RuleEngine:
    def __init__(self, yaml_file):
        with open(yaml_file) as f:
            self.rules = yaml.load(f, Loader=yaml.FullLoader)['rules']


    def check_rule(self, log, rule):
        for condition in rule['conditions']:
            if condition['when']['field'] in log and condition['when']['contains'] in log[condition['when']['field']]:
                return True
        return False


    def process_rule(rule, log):
        ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        username_pattern = re.compile(r"user (\S+)")
        hostname_pattern = re.compile(r"from (\S+)")
        timestamp_pattern = re.compile(r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})")

        ip_match = ip_pattern.search(log['Message'])
        username_match = username_pattern.search(log['Message'])
        hostname_match = hostname_pattern.search(log['Message'])
        timestamp_match = timestamp_pattern.search(log['Timestamp'])

        ip = ip_match.group() if ip_match else ''
        username = username_match.group(1) if username_match else ''
        hostname = hostname_match.group(1) if hostname_match else ''
        timestamp = timestamp_match.group(1) if timestamp_match else ''

        for action in rule['actions']:
            if 'log' in action:
                log_message = action['log'].format(IPV4=ip, Timestamp=timestamp, hostname=hostname, user=username)
                print(log_message)
            if 'file' in action:
                with open(action['file'], 'a') as f:
                    f.write(f'{rule["name"]}: {log}\n')

    def run(self, index, query=None, size=1000):
        query = query or {'query': {'match_all': {}}}
        search_result = es_query(index=index, body=query, size=size)
        for hit in search_result['hits']['hits']:
            log = hit['_source']
            for rule in self.rules:
                if self.check_rule(log, rule):
                    self.process_rule(log, rule)

