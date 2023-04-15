import yaml
from collections import defaultdict
import datetime
from elasticsearch import Elasticsearch, exceptions
from elasticsearch_dsl import Search, Q
from smtp import GmailSender
import sys

class HttpBruteforce:
    def __init__(self, rules_file_path, elasticsearch_hosts):
        # Load YAML rule from file
        with open(rules_file_path, 'r') as f:
            self.rule = yaml.safe_load(f)
        
        # Initialize data structure to store failed login attempts
        self.ip_attempts = defaultdict(int)
        self.http_url_attempts = defaultdict(lambda: defaultdict(int))
        self.ip_last_attempt_time = {}

        # Connect to Elasticsearch
        self.es = Elasticsearch(elasticsearch_hosts)

    def process_apache_logs(self, index_name):
        query = Q('exists', field='username_pass')
        s = Search(using=self.es, index=index_name).query(query)


        # Process log entries
        try:
            for hit in s.scan():
                # Extract relevant fields (e.g., IP address, timestamp, URL)
                http_ip_address = hit.client
                Timestamp=datetime.datetime.strptime(hit['timestamp'],'%d/%b/%Y:%H:%M:%S %z')
                http_url=hit.url
                check_timestamp_of_log = datetime.datetime.fromisoformat(hit['@timestamp'][:-1]).strftime("%Y-%m-%d")
                check_current_time=datetime.datetime.now().strftime("%Y-%m-%d")
                
                # Update the attempt count for the IP address and URL
                self.ip_attempts[http_ip_address] += 1
                self.http_url_attempts[http_url][http_ip_address] += 1
                
                # Check if the same IP address has made attempts within the last 10 seconds
                if str(check_current_time)==str(check_timestamp_of_log):
                    if http_ip_address in self.ip_last_attempt_time:
                        last_attempt_time = self.ip_last_attempt_time[http_ip_address]
                        time_diff = Timestamp - last_attempt_time
                        
                        if time_diff.total_seconds() < self.rule['conditions'][1]['http_timeframe']:
                            self.ip_attempts[http_ip_address] += 1
                            if self.http_url_attempts[http_url][http_ip_address] >= self.rule['conditions'][1]['http_count']:
                                alert=(f"ALERT: IP address {http_ip_address} has made {self.rule['conditions'][1]['http_count']} attempts on {http_url} within {self.rule['conditions'][1]['http_timeframe']} seconds!")
                                
                                #Sending alert if incident is occurred.
                                sender = GmailSender('env.txt')
                                sender.send_email('Incident Detected', alert)
                                now = datetime.datetime.now()
                                formatted_date = now.strftime("%Y-%m-%d %H:%M:%S")
                                send_log_index='myindex'
                                detected_incident={'Timestamp':formatted_date,'IPV4':http_ip_address,'Message':alert,'URL':http_url}
                                self.es.index(index=send_log_index, document=detected_incident)
                        #changing value of ip address attempt to 1 and changing IP alst attemt to previous timestamp.
                        else:
                            self.ip_last_attempt_time[http_ip_address] = Timestamp
                            self.http_url_attempts[http_url][http_ip_address] = 1
                    #changing value of ip address attempt to 1 and changing IP alst attemt to previous timestamp.
                    else:
                        self.ip_last_attempt_time[http_ip_address] = Timestamp
                        self.http_url_attempts[http_url][http_ip_address] = 1

                        self.http_url_attempts[http_url][http_ip_address] = 1
        #Error handling if the extract field is not present elasticsearch Index                  
        except AttributeError:
            print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
            print('The field you entered doesnot exist. ')
            print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
        except KeyboardInterrupt:
            sys.exit()
# try:  
#     while True:                  
#         # Create an instance of RuleEngine
#         engine = HttpBruteforce('rules.yaml', ['http://3.229.13.155:9200'])

#         # Call the process_logs method to run the rule engine
#         engine.process_apache_logs('access_log')
# except exceptions.ConnectionError:
#      print("\n+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
#      print('Elascticsearch not connected. Elasticsearch seems down. \n')
#      print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n")
#      sys.exit()
# except KeyboardInterrupt:
#       sys.exit()