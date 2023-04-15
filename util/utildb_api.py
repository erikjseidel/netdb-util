from pymongo import MongoClient, errors
from pymongo.errors import *

from .decorators import util_internal

class utilDB:

    def __init__(self, collection):
        self.client = MongoClient("mongodb://localhost:27017/")  

        database = 'utildb'
        collection = collection
        cursor = self.client[database]
        self.collection = cursor[collection]


    @util_internal
    def read(self, query = {}, projection = {}):
        documents = self.collection.find(query, projection)

        out = [
                {
                    item: data[item] 
                    for item in data if item != '_id'
                } 
                for data in documents
              ]

        if len(out) == 0:
            return False, None, 'No documents found'

        return True, out, '%s documents read' % len(out)


    @util_internal
    def write_one(self, document):
        response = self.collection.insert_one(document)

        return True, None, str(response.inserted_id) + ' created'


    @util_internal
    def replace_one(self, filt, document):
        response = self.collection.replace_one(filt, document, upsert=True)

        if response.modified_count > 0:
            return True, None, 'document modified'

        return True, None, 'document added'


    @util_internal
    def delete(self, filt):
        response = self.collection.delete_many(filt)
        if response.deleted_count == 0:
            return False, None, 'Nothing deleted'

        doc = "document" if response.deleted_count == 1 else "documents"
        return True, None, '%s %s deleted' % (response.deleted_count, doc)
