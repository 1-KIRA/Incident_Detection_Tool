from ConnectAndQueryInElastic import ElasticsearchQuery
from ConnectAndQueryInElastic import ElasticsearchIndexExtractor
# from ruleengine import RuleEngine
# from RuleEngineTest import detect_ssh_bruteforce
import yaml

#threshold to detect bruteforce
threshold=2

# Create ElasticsearchQuery object to query Elasticsearch index
es_query = ElasticsearchQuery()

# Create ElasticsearchIndexExtractor object to extract data from Elasticsearch index
es_extractor = ElasticsearchIndexExtractor(
    index="parsed_auth_log",
    fields=["Timestamp", "action", "User", "IPV4","message"]
)

# Extract data from Elasticsearch index
data = es_extractor.extract_fields()
extracted_documents = es_extractor.extract_fields()

# result=[]
# for log_line in data:
#     result.append(log_line['Timestamp','action', 'User', "IPV4"])
# print(result[0])


with open ('rules.yaml', 'r') as stream:
    data_yaml=yaml.safe_load(stream)

# print(data_yaml['rules'][0])


for key, values in data_yaml['rules'][0].items():
    #for fields in indexed:
    #print(key)
    if key == "conditions":
        a = [l['when']['contains'] for l in values]


print(a)

# AND if there are multiple thing to be checked
for i in range(len(data)):
    if 'action' in data[i]:
        action= (data[i]['action'])
        time=(data[i]['Timestamp'])
        print(action,time)
