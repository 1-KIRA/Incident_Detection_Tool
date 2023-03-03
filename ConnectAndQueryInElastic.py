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

'''The ElasticsearchQuery class is created to execute arbitrary Elasticsearch queries on a specified index

'''
class ElasticsearchQuery:
    def __init__(self):
        self.es = Elasticsearch(['http://3.229.13.155:9200'])
    
    def search(self, index, query):
        res = self.es.search(index=index, body=query)
        hits = res['hits']['hits']
        return [hit['_source'] for hit in hits]