from pymongo import MongoClient
from pymongo.errors import PyMongoError

from app.config import settings


class DatabaseClient:
    def __init__(self):
        self.mode = "memory"
        self._memory_reports: list[dict] = []
        self._client = None
        self._collection = None

        try:
            self._client = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=1500)
            self._client.admin.command("ping")
            db = self._client[settings.mongo_db]
            self._collection = db[settings.mongo_collection]
            self._collection.create_index("report_id", unique=True)
            self._collection.create_index("created_at")
            self._collection.create_index("severity")
            self._collection.create_index("extracted_fields.vulnerability_type")
            self.mode = "mongo"
        except Exception:
            self._client = None
            self._collection = None

    def insert_report(self, payload: dict) -> None:
        if self.mode == "mongo" and self._collection is not None:
            try:
                self._collection.insert_one(payload)
                return
            except PyMongoError:
                pass
        self._memory_reports.append(payload)

    def list_reports(self, limit: int = 100) -> list[dict]:
        if self.mode == "mongo" and self._collection is not None:
            docs = self._collection.find({}, {"_id": 0}).sort("created_at", -1).limit(limit)
            return list(docs)
        return list(reversed(self._memory_reports[-limit:]))

    def get_report(self, report_id: str) -> dict | None:
        if self.mode == "mongo" and self._collection is not None:
            return self._collection.find_one({"report_id": report_id}, {"_id": 0})
        for item in self._memory_reports:
            if item.get("report_id") == report_id:
                return item
        return None
