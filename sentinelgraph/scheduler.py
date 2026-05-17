"""Simple incremental sync scheduler."""

from __future__ import annotations

import threading
import time
from typing import Dict

from .models import SchedulerJobInput, SourceImportRequest
from .source_control import HistoryImporter


class IncrementalScheduler:
    def __init__(self, importer: HistoryImporter):
        self.importer = importer
        self.jobs: Dict[str, SchedulerJobInput] = {}
        self.last_results: Dict[str, Dict[str, object]] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._stop = threading.Event()

    def add_job(self, item: SchedulerJobInput) -> Dict[str, object]:
        self.jobs[item.job_id] = item
        return {"job": item.model_dump(), "status": "registered"}

    def run_once(self, job_id: str) -> Dict[str, object]:
        job = self.jobs[job_id]
        if not job.enabled:
            result = {"status": "skipped", "reason": "disabled"}
        else:
            result = self.importer.import_from_request(
                SourceImportRequest(
                    provider=job.provider,
                    repo=job.repo,
                    token_env=job.token_env,
                    limit=job.limit,
                )
            ).model_dump()
        self.last_results[job_id] = result
        return result

    def start(self, job_id: str) -> Dict[str, object]:
        if job_id in self._threads and self._threads[job_id].is_alive():
            return {"status": "already-running"}

        def loop():
            while not self._stop.is_set():
                try:
                    self.run_once(job_id)
                except Exception as exc:
                    self.last_results[job_id] = {"status": "failed", "error": str(exc)}
                time.sleep(max(10, self.jobs[job_id].interval_seconds))

        thread = threading.Thread(target=loop, daemon=True)
        self._threads[job_id] = thread
        thread.start()
        return {"status": "started", "job_id": job_id}

    def stop(self) -> Dict[str, object]:
        self._stop.set()
        return {"status": "stopping"}

    def status(self) -> Dict[str, object]:
        return {
            "jobs": {job_id: job.model_dump() for job_id, job in self.jobs.items()},
            "last_results": self.last_results,
            "running": [job_id for job_id, thread in self._threads.items() if thread.is_alive()],
        }
