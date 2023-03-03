from elasticsearch import Elasticsearch

'''The ElasticsearchIndexExtractor class is created to extract specific fields 
from documents in an Elasticsearch index using a specified query'''
class ElasticsearchIndexExtractor:
    def __init__(self, index, fields):
        self.index = index
        self.fields = fields
        self.es = Elasticsearch(['http://3.229.13.155:9200'])
    
    #extract_fields  executes the query and returns a list of documents containing only the specified fields.
    def extract_fields(self):
        # Define the search query
        query = {
            "_source": self.fields,
            "query": {
                "match_all": {}
            }
        }

        # Execute the search query and extract the specified fields from each hit
        response = self.es.search(index=self.index, body=query)
        hits = response['hits']['hits']
        documents = []
        for hit in hits:
            document = {}
            for field in self.fields:
                if field in hit['_source']:
                    document[field] = hit['_source'][field]
            documents.append(document)

        # Return the list of documents containing only the specified fields
        return documents
# Define the index name and fields to extract
index_name = "parsed_auth_log"
fields = ["Timestamp","hostname","sesssion","action","User","IPV4","tty","Rhost","auth_failure_user","Message","Logged_in_user"]

# Create an instance of the ElasticsearchIndexExtractor class
extractor = ElasticsearchIndexExtractor(index_name, fields)
# Call the extract_fields method and store the result in a variable
extracted_documents = extractor.extract_fields()

# Print the extracted documents
for doc in extracted_documents:
    print(doc)


'''The ElasticsearchQuery class is created to execute arbitrary Elasticsearch queries on a specified index

'''
class ElasticsearchQuery:
    def __init__(self, host, port):
        self.es = Elasticsearch([{'host': host, 'port': port}])
    
    def search(self, index, query):
        res = self.es.search(index=index, body=query)
        hits = res['hits']['hits']
        return [hit['_source'] for hit in hits]