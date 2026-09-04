from functools import lru_cache

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database

from core.config import get_settings


@lru_cache
def get_client() -> MongoClient:
    settings = get_settings()
    return MongoClient(settings.MONGO_URI, serverSelectionTimeoutMS=3000)


def get_database() -> Database:
    settings = get_settings()
    return get_client()[settings.MONGO_DATABASE]


def get_scan_logs() -> Collection:
    settings = get_settings()
    return get_database()[settings.MONGO_COLLECTION]
