import uuid

from app.analytics import build_analytics
from app.database import DatabaseClient


db_client = DatabaseClient()


def save_report(record: dict) -> str:
    report_id = record.get("report_id") or str(uuid.uuid4())
    payload = {**record, "report_id": report_id}
    db_client.insert_report(payload)
    return report_id


def list_reports(limit: int = 100) -> list[dict]:
    return db_client.list_reports(limit)


def get_report(report_id: str) -> dict | None:
    return db_client.get_report(report_id)


def analytics_summary() -> dict:
    return build_analytics(db_client.list_reports(limit=5000))


def storage_mode() -> str:
    return db_client.mode
