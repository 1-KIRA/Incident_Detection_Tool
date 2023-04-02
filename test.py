from elasticsearch import Elasticsearch
from datetime import datetime
from elasticsearch_dsl import Search, Q

# Connect to Elasticsearch
es = Elasticsearch(["http://3.229.13.155:9200"])

# Get today's date
today = datetime.now().date()

# Define the Elasticsearch query
s = Search(using=es, index="myindex").query(
    Q('match', Timestamp=str(today))
)

# Execute the query and get the results
response = s.execute()

# Print the hits (results)
for hit in response:
    print(hit)


