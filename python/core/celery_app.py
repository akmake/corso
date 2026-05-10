import os
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

app = Celery(
    "webint_tasks",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["core.tasks"]
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="Asia/Jerusalem",
    enable_utc=True,
    task_track_started=True,
)