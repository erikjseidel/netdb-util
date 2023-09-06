from pymongo import MongoClient, errors
from pymongo.errors import *

from config.secrets import MONGO_URL


class utilDB:
    def __init__(self, collection):
        self.client = MongoClient(MONGO_URL)

        database = 'utildb'
        collection = collection
        cursor = self.client[database]
        self.collection = cursor[collection]

    def read(self, query={}, projection={}):
        documents = self.collection.find(query, projection)

        out = [
            {item: data[item] for item in data if item != '_id'} for data in documents
        ]

        if len(out) == 0:
            return None

        return out

    def write_one(self, document):
        response = self.collection.insert_one(document)

        return str(response.inserted_id)

    def replace_one(self, filt, document):
        response = self.collection.replace_one(filt, document, upsert=True)

        return response.modified_count

    def delete(self, filt):
        response = self.collection.delete_many(filt)

        return response.deleted_count
