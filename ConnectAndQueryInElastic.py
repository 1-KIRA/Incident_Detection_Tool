# Import the function
from elasticsearch import Elasticsearch

def extract_fields_from_index(index, fields):
    # Connect to Elasticsearch cluster
    es = Elasticsearch(['http://3.229.13.155:9200'])
    
    # Define the search query
    query = {
        "_source": fields,
        "query": {
            "match_all": {}
        }
    }
    
    # Execute the search query and extract the specified fields from each hit
    response = es.search(index=index, body=query)
    hits = response['hits']['hits']
    documents = []
    for hit in hits:
        document = {}
        for field in fields:
            if field in hit['_source']:
                document[field] = hit['_source'][field]
        documents.append(document)
    
    # Return the list of documents containing only the specified fields
    return documents

# Define the index name and fields to extract
index_name = "parsed_auth_log"
fields = ["Timestamp","hostname","sesssion","action","User","IPV4","tty","Rhost","auth_failure_user","Message","Logged_in_user"]

# Call the function and store the result in a variable
extracted_documents = extract_fields_from_index(index_name, fields)


# Print the extracted documents
for doc in extracted_documents:
    print(doc)
