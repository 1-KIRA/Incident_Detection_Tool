from ConnectAndQueryInElastic import ElasticsearchQuery
from ConnectAndQueryInElastic import ElasticsearchIndexExtractor
from ruleengine import RuleEngine
import yaml


# Create ElasticsearchQuery object to query Elasticsearch index
es_query = ElasticsearchQuery()

# Create ElasticsearchIndexExtractor object to extract data from Elasticsearch index
es_extractor = ElasticsearchIndexExtractor(
    index="parsed_auth_log",
    fields=["Timestamp", "hostname", "action", "tty", "Rhost", "auth_failure_user", "User", "IPV4", "Message", "Logged_in_user"],
)

# Extract data from Elasticsearch index
data = es_extractor.extract_fields()
extracted_documents = es_extractor.extract_fields()

rule_engine = RuleEngine('Rules.yml')

for logs in extracted_documents:
    actions = rule_engine.match(logs)
    print(actions)