"""Реестр фоновых задач + SSE-события (ТЗ §15).

Модель:
- JobManager хранит все jobs in-memory (dict под threading.RLock).
- Каждый job запускается в отдельном daemon-потоке.
- Прогресс отдаётся через queue.Queue; SSE-эндпоинт читает её.
- Отмена: job.cancel() выставляет флаг; worker обязан периодически
  проверять cancel_check() и корректно завершаться.
- По завершении job хранится N часов (retention), потом GC.

Jobs не переживают перезапуск процесса — это осознанно: они привязаны
к HTTP-сессии и пересоздаются при необходимости.
"""
from __future__ import annotations

import json
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


# ---------------------------------------------------------------------------
# Состояния
# ---------------------------------------------------------------------------

class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES = {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}


# ---------------------------------------------------------------------------
# События SSE
# ---------------------------------------------------------------------------

@dataclass
class JobEvent:
    """Событие job'а для SSE.

    event_type:
        started    — job начал работу
        progress   — msg + frac
        log        — текстовое сообщение
        result     — финальный результат (dict)
        error      — ошибка (code, message)
        done       — терминальное событие
    """
    event_type: str
    data: dict[str, Any]
    ts: float = field(default_factory=time.time)

    def to_sse(self) -> str:
        """Сериализует в SSE-формат. Path и прочие нестандартные типы — в str."""
        payload = json.dumps(
            {"ts": self.ts, **self.data},
            ensure_ascii=False,
            default=_json_default,
        )
        return f"event: {self.event_type}\ndata: {payload}\n\n"


def _json_default(o: Any) -> Any:
    """JSON-сериализатор: Path → str, bytes → hex, остальное — str()."""
    from pathlib import Path as _Path
    if isinstance(o, _Path):
        return str(o)
    if isinstance(o, (bytes, bytearray)):
        return bytes(o).hex()
    if isinstance(o, set):
        return sorted(o)
    # последний шанс — привести к строке
    return str(o)
# ---------------------------------------------------------------------------
# Job
# ---------------------------------------------------------------------------

class Job:
    def __init__(self, job_id: str, kind: str, params: dict[str, Any]):
        self.id = job_id
        self.kind = kind
        self.params = params
        self.state = JobState.PENDING
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.result: Optional[dict[str, Any]] = None
        self.error: Optional[dict[str, Any]] = None
        self._cancel_flag = threading.Event()
        # ← ИЗМЕНЕНО: list вместо Queue, чтобы subscribe+replay были
        # атомарными под одним lock. См. subscribe_with_snapshot.
        self._events: list[JobEvent] = []
        self._events_max = 10000
        self._subscribers: list[queue.Queue[JobEvent]] = []
        self._lock = threading.RLock()

    # --- Отмена ---

    def cancel(self) -> None:
        """Запрашивает отмену. Worker должен сам проверить и завершиться."""
        self._cancel_flag.set()

    def is_cancelled(self) -> bool:
        return self._cancel_flag.is_set()

    # --- Прогресс из worker'а ---

    def emit(self, event_type: str, **data: Any) -> None:
        """Публикует событие: кладёт в основной буфер и рассылает подписчикам."""
        ev = JobEvent(event_type=event_type, data=data)
        with self._lock:
            self._events.append(ev)
            if len(self._events) > self._events_max:
                # отбрасываем самые старые для длинных прогонов
                del self._events[: len(self._events) - self._events_max]
            for q in list(self._subscribers):
                try:
                    q.put_nowait(ev)
                except queue.Full:
                    pass

    def progress(self, msg: str, frac: float) -> None:
        self.emit("progress", message=msg, fraction=max(0.0, min(1.0, frac)))

    def log(self, msg: str) -> None:
        self.emit("log", message=msg)

    # --- Подписка для SSE ---

    def subscribe(self) -> queue.Queue[JobEvent]:
        """Возвращает очередь, в которую будут приходить новые события."""
        q: queue.Queue[JobEvent] = queue.Queue(maxsize=1000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def subscribe_with_snapshot(self) -> tuple[queue.Queue[JobEvent], list[JobEvent]]:
        """Атомарно: подписка + снимок уже накопленных событий.
        Между subscribe и replay не может проскочить событие."""
        with self._lock:
            q: queue.Queue[JobEvent] = queue.Queue(maxsize=1000)
            self._subscribers.append(q)
            snapshot = list(self._events)
        return q, snapshot

    def unsubscribe(self, q: queue.Queue[JobEvent]) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def replay_events(self) -> list[JobEvent]:
        """Только для отладки. В sse_stream НЕ использовать — race."""
        with self._lock:
            return list(self._events)

    def finish(self, state: JobState, result: Optional[dict] = None,
               error: Optional[dict] = None) -> None:
        with self._lock:
            if self.state in TERMINAL_STATES:
                return
            self.state = state
            self.finished_at = time.time()
            self.result = result
            self.error = error
        if state == JobState.COMPLETED:
            self.emit("result", result=result or {})
        elif state == JobState.FAILED:
            self.emit("error", error=error or {"code": "UNKNOWN", "message": "unknown error"})
        elif state == JobState.CANCELLED:
            self.emit("log", message="cancelled")
        self.emit("done", state=state.value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "state": self.state.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "result": self.result,
            "error": self.error,
            "params": self.params,
        }


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class JobManager:
    """Реестр задач. Singleton в рамках процесса."""

    def __init__(self, retention_seconds: float = 300.0):
        self._jobs: dict[str, Job] = {}
        self._lock = threading.RLock()
        self._retention = retention_seconds

    def create(self, kind: str, params: Optional[dict[str, Any]] = None) -> Job:
        self.gc()   # ← очистка завершённых перед созданием нового
        job_id = uuid.uuid4().hex[:12]
        job = Job(job_id, kind, params or {})
        with self._lock:
            self._jobs[job_id] = job
        return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, kind: Optional[str] = None,
             state: Optional[JobState] = None) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if kind is not None:
            jobs = [j for j in jobs if j.kind == kind]
        if state is not None:
            jobs = [j for j in jobs if j.state == state]
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None:
            return False
        if job.state in TERMINAL_STATES:
            return False
        job.cancel()
        return True

    def run(
        self,
        kind: str,
        worker: Callable[[Job], dict[str, Any]],
        params: Optional[dict[str, Any]] = None,
    ) -> Job:
        """Создаёт job и запускает его в отдельном потоке.

        worker(job) должен:
          - периодически вызывать job.progress(msg, frac)
          - проверять job.is_cancelled() и при True бросать JobCancelled
          - вернуть dict — результат; он попадёт в job.result
        """
        job = self.create(kind, params)

        def _runner() -> None:
            job.state = JobState.RUNNING
            job.started_at = time.time()
            job.emit("started", kind=kind)
            try:
                result = worker(job)
                if job.is_cancelled():
                    job.finish(JobState.CANCELLED)
                else:
                    job.finish(JobState.COMPLETED, result=result)
            except JobCancelled:
                job.finish(JobState.CANCELLED)
            except BaseException as e:
                import traceback
                job.finish(
                    JobState.FAILED,
                    error={
                        "code": type(e).__name__,
                        "message": str(e),
                        "traceback": traceback.format_exc(),
                    },
                )

        t = threading.Thread(target=_runner, name=f"job-{job.id}", daemon=True)
        t.start()
        return job

    def gc(self) -> int:
        """Удаляет завершённые jobs старше retention. Возвращает число удалённых."""
        cutoff = time.time() - self._retention
        removed = 0
        with self._lock:
            for jid in list(self._jobs.keys()):
                j = self._jobs[jid]
                if j.state in TERMINAL_STATES and j.finished_at and j.finished_at < cutoff:
                    del self._jobs[jid]
                    removed += 1
        return removed
    
    def clear_completed(self) -> int:
        """Удаляет все завершённые jobs. Возвращает число удалённых."""
        removed = 0
        with self._lock:
            for jid in list(self._jobs.keys()):
                j = self._jobs[jid]
                if j.state in TERMINAL_STATES:
                    del self._jobs[jid]
                    removed += 1
        return removed


class JobCancelled(Exception):
    """Исключение для worker'а: сигнал о graceful-отмене."""
    pass


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_manager: Optional[JobManager] = None
_manager_lock = threading.Lock()


def get_job_manager() -> JobManager:
    global _manager
    with _manager_lock:
        if _manager is None:
            _manager = JobManager()
        return _manager


# ---------------------------------------------------------------------------
# SSE-генератор
# ---------------------------------------------------------------------------

def sse_stream(job: Job, heartbeat: float = 15.0):
    """Генератор SSE-событий для Flask response.

    Отдаёт накопленные события, затем новые из очереди подписки.
    Завершается, когда job достиг терминального состояния и все события
    отправлены.
    """
    # ← ИЗМЕНЕНО: атомарная подписка + снимок, чтобы не потерять событие,
    # которое появится между replay_events и subscribe.
    q, snapshot = job.subscribe_with_snapshot()
    try:
        for ev in snapshot:
            yield ev.to_sse()

        if job.state in TERMINAL_STATES and q.empty():
            yield "event: close\ndata: {}\n\n"
            return

        last_heartbeat = time.time()
        while True:
            try:
                ev = q.get(timeout=1.0)
                yield ev.to_sse()
                if ev.event_type == "done":
                    yield "event: close\ndata: {}\n\n"
                    return
            except queue.Empty:
                now = time.time()
                if now - last_heartbeat >= heartbeat:
                    yield ": heartbeat\n\n"
                    last_heartbeat = now
                if job.state in TERMINAL_STATES:
                    yield "event: close\ndata: {}\n\n"
                    return
    finally:
        job.unsubscribe(q)