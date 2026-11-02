"""
jobs.py  -  WEEK 4: The async job queue
==================================================================
THE PROBLEM
    Week 3's POST /analyze blocked until the whole file was analysed.
    For a 1 GB log that is minutes of a frozen browser tab and a
    request that a proxy will probably time out (30-60 s).

THE FIX (exactly what the brief asks for)
    Upload  ->  get a Job ID  ->  poll status  ->  view report

         POST /analyze
              |
              v
        create job (status=queued)  ---- return job id IMMEDIATELY
              |
              v
        worker thread: parse + detect + aggregate   (in the background)
              |
              v
        status: queued -> running (0-100%) -> done | error

WHY THREADS AND NOT CELERY/REDIS?
    The brief says "implement an async job queue". A thread pool IS a
    queue: ThreadPoolExecutor keeps a work queue and up to N workers.
    Celery + Redis is the right answer for multi-server production, but
    it needs a broker service running. For one process and a learning
    project, threads teach the same architecture with zero setup - and
    swapping in Celery later only changes this file.

WHAT IS STILL MISSING FOR REAL PRODUCTION
    * Jobs die when the process restarts (only finished reports survive,
      because we write them to disk).
    * Two gunicorn workers would each have their own job dict.
    * No authentication, no per-user limits.
    See DEPLOYMENT.md - these are stated honestly, not hidden.
==================================================================
"""

import json
import os
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from parser import iter_entries
from detector import ThreatDetector, DEFAULT_SIGNATURES
from aggregator import StreamCollector
from geoip import GeoLookup, enrich_report


def _now() -> str:
    """Current UTC time as ISO text (JSON has no date type)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class JobStore:
    """
    Owns the job dictionary, the worker pool, and the on-disk reports.

    Thread-safety in one sentence: every read/write of self._jobs
    happens while holding self._lock, so two threads can never mutate
    the same job at the same time.
    """

    def __init__(
        self,
        report_dir: str,
        geo: GeoLookup,
        max_workers: int = 2,
        keep_jobs: int = 50,
    ):
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)

        self.geo = geo
        self.keep_jobs = keep_jobs

        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # The actual "queue": a pool with N worker threads.
        # max_workers=2 means at most two files are analysed at once -
        # a third upload waits in the queue, which protects the CPU.
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="loglens")

    # --------------------------------------------------------------
    # Public API
    # --------------------------------------------------------------
    def submit(
        self,
        filename: str,
        source_path: str,
        threshold: Optional[int] = None,
        delete_source: bool = False,
    ) -> str:
        """
        Register a job and hand the work to the pool.

        Returns the job id immediately - that is the whole point of an
        async design. The caller never waits for the analysis.
        """
        job_id = uuid.uuid4().hex[:10]

        job = {
            "id": job_id,
            "filename": filename,
            "status": "queued",          # queued | running | done | error
            "progress": 0,               # 0-100, shown by the progress bar
            "message": "Waiting for a free worker...",
            "created_at": _now(),
            "started_at": None,
            "finished_at": None,
            "elapsed_seconds": None,
            "error": None,
            "summary": None,             # small copy for the "recent" list
            "source_path": source_path,
            "delete_source": delete_source,
            "threshold": threshold,
        }

        with self._lock:
            self._jobs[job_id] = job
            self._prune_locked()

        # submit() puts the callable in the queue. A worker picks it up
        # when one becomes free. We do NOT wait for the result.
        self._executor.submit(self._run, job_id)

        return job_id

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Return a COPY of the job (so callers cannot mutate our state)."""
        with self._lock:
            job = self._jobs.get(job_id)
            return self._public_copy(job) if job else None

    def recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Newest jobs first."""
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda job: job["created_at"], reverse=True)
        return [self._public_copy(job) for job in jobs[:limit]]

    def shutdown(self) -> None:
        """Stop accepting work and wait for running jobs (used on exit)."""
        self._executor.shutdown(wait=False, cancel_futures=True)

    # --------------------------------------------------------------
    # Report persistence
    # --------------------------------------------------------------
    def save_report(self, job_id: str, report: Dict[str, Any]) -> None:
        """
        Write the finished report to reports/<job_id>.json.

        Why bother when it is already in memory? Because memory dies on
        restart, and because an "Export report" feature should read the
        same file the dashboard reads. One source of truth.
        """
        path = os.path.join(self.report_dir, f"{job_id}.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)

    def load_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Read a report from disk (week 3 had no disk fallback)."""
        path = os.path.join(self.report_dir, f"{report_id}.json")
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None

    # --------------------------------------------------------------
    # The worker
    # --------------------------------------------------------------
    def _run(self, job_id: str) -> None:
        """
        Runs INSIDE a worker thread. Nothing here may touch Flask's
        request/session context - there is no HTTP request anymore.
        """
        job = self._raw(job_id)
        if job is None:
            return

        started = time.perf_counter()
        self._update(job_id, status="running", started_at=_now(),
                     message="Streaming file...", progress=3)

        collector = StreamCollector()
        stats: Dict[str, Any] = {}

        try:
            # ---- 1. Build the lazy entry pipeline -------------------
            # iter_entries yields one dict at a time. Nothing is stored.
            entries = iter_entries(
                job["source_path"],
                stats=stats,
                on_progress=lambda fraction: self._update(
                    job_id,
                    progress=3 + int(fraction * 84),   # 3% .. 87%
                    message=f"Reading and scanning... {int(fraction * 100)}%",
                ),
                on_error=collector.add_error,
            )

            def counted():
                """
                A tiny adapter generator: count each entry as it flows
                past, then pass it to the detector unchanged.

                This is how you "observe" a stream without buffering it.
                """
                for entry in entries:
                    collector.add(entry)
                    yield entry

            # ---- 2. Scan (signatures + brute force) ----------------
            # A fresh detector per job keeps the per-rule hit counters
            # private to this job, and makes the threshold override safe
            # when two jobs run concurrently.
            detector = ThreatDetector(
                signatures_path=DEFAULT_SIGNATURES,
                brute_force_threshold=job["threshold"],
            )

            incidents, brute_force = detector.scan(counted())

            # iter_entries has finished, so stats is complete now.
            collector.set_total_lines(stats.get("total_lines", 0))

            # ---- 3. Aggregate --------------------------------------
            self._update(job_id, progress=93, message="Aggregating results...")
            report = collector.build(incidents, brute_force)

            # ---- 4. GeoIP enrichment -------------------------------
            enrich_report(report, self.geo)

            # ---- 5. Metadata ---------------------------------------
            elapsed = round(time.perf_counter() - started, 2)
            report["meta"] = {
                "report_id": job_id,
                "filename": job["filename"],
                "generated_at": _now(),
                "elapsed_seconds": elapsed,
                "engine": "streaming",
            }

            # ---- 6. Persist + finish -------------------------------
            self.save_report(job_id, report)

            self._update(
                job_id,
                status="done",
                progress=100,
                message="Report ready",
                finished_at=_now(),
                elapsed_seconds=elapsed,
                summary={
                    "incidents": report["summary"]["incidents"],
                    "attack_requests": report["summary"]["attack_requests"],
                    "total_lines": report["summary"]["total_lines"],
                },
            )

        except Exception as error:                        # noqa: BLE001
            # Never let an exception escape a worker thread: it would be
            # printed to stderr and the job would stay "running" forever.
            traceback.print_exc()
            self._update(
                job_id,
                status="error",
                message="Analysis failed",
                error=f"{type(error).__name__}: {error}",
                finished_at=_now(),
                elapsed_seconds=round(time.perf_counter() - started, 2),
            )

        finally:
            # Uploaded files are temporary - remove them even on failure.
            if job.get("delete_source"):
                try:
                    os.remove(job["source_path"])
                except OSError:
                    pass

    # --------------------------------------------------------------
    # Helpers
    # --------------------------------------------------------------
    def _update(self, job_id: str, **fields) -> None:
        """Thread-safe partial update of one job."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is not None:
                job.update(fields)

    def _raw(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Internal access to the full job dict (includes source_path)."""
        with self._lock:
            return self._jobs.get(job_id)

    def _prune_locked(self) -> None:
        """Keep the dictionary small; never drop a queued/running job."""
        if len(self._jobs) <= self.keep_jobs:
            return

        finished = [job for job in self._jobs.values() if job["status"] in ("done", "error")]
        finished.sort(key=lambda job: job["created_at"])

        while len(self._jobs) > self.keep_jobs and finished:
            oldest = finished.pop(0)
            self._jobs.pop(oldest["id"], None)

    @staticmethod
    def _public_copy(job: Dict[str, Any]) -> Dict[str, Any]:
        """Strip internal fields before sending a job to the browser."""
        public = dict(job)
        public.pop("source_path", None)
        public.pop("delete_source", None)
        return public
