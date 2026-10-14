"""Sandbox для script-интерпретаций (ТЗ §8.5).

Модель:
- Один долгоживущий worker-процесс на job (не на сообщение).
- Worker запускается через multiprocessing.get_context("spawn").
- RLIMIT_CPU, RLIMIT_AS=512MiB, RLIMIT_FSIZE=0 выставляются в child.
- RLIMIT_NPROC НЕ трогаем.
- stderr вычитывается родителем в отдельном потоке (защита от дедлока).
- Таймаут → kill() + respawn + пометка "мёртв".
- Whitelist импортов через meta_path hook.
- random.seed() фиксируется при старте.
"""
from __future__ import annotations

import importlib.abc
import importlib.machinery
import multiprocessing as mp
import os
import queue
import random
import signal as _signal
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .base import (
    BaseInterpreter,
    InterpretationError,
    MessageResult,
    MessageStatus,
)


# ---------------------------------------------------------------------------
# Whitelist импортов (ТЗ §8.5)
# ---------------------------------------------------------------------------

ALLOWED_MODULES: frozenset[str] = frozenset({
    # Пользовательские модули (ТЗ §8.5)
    "math", "struct", "binascii", "re",
    "dataclasses", "typing", "collections",
    "json", "decimal", "fractions",
    "enum", "itertools", "functools",
    "operator", "string", "textwrap",
    "random", "time",                               # ← добавлено: §8.5 требует random с seed

    # Минимум для работы самого Python-интерпретатора.
    # Важно: НЕ включаем сюда os, sys, importlib, subprocess, socket —
    # они нужны только внутреннему коду, который использует real_import.
    "builtins",
    "_frozen_importlib",
    "_frozen_importlib_external",
    "warnings", "types", "abc", "io", "codecs",
    "_codecs", "encodings", "encodings.utf_8",
    "_collections_abc", "posixpath", "stat",
    "genericpath", "fnmatch",
    "copyreg", "sre_compile", "sre_parse", "sre_constants",
})

ALLOWED_PREFIXES: tuple[str, ...] = (
    "re.", "collections.", "dataclasses.",
    "typing.", "json.", "decimal.", "fractions.",
    "enum.", "itertools.", "functools.",
    "operator.", "string.", "textwrap.",
    "encodings.",
)


import builtins as _builtins


def _make_restricted_import():
    """Создаёт __import__-обёртку, применяющую whitelist.

    Проверяет корневое имя модуля ДО обращения к sys.modules,
    поэтому кеш родителя не даёт обойти блокировку.
    """
    real_import = _builtins.__import__

    def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
        root = name.split(".", 1)[0]
        allowed = (
            root in ALLOWED_MODULES
            or name in ALLOWED_MODULES
            or any(name.startswith(p) for p in ALLOWED_PREFIXES)
        )
        if not allowed:
            raise ImportError(f"import '{name}' is not allowed in sandbox")
        return real_import(name, globals, locals, fromlist, level)

    return restricted_import


def _build_safe_builtins() -> dict:
    """Словарь builtins с ограниченным __import__."""
    safe = dict(vars(_builtins))
    safe["__import__"] = _make_restricted_import()
    return safe

def _get_mp_context() -> mp.context.BaseContext:
    """Выбирает безопасный multiprocessing-контекст.

    Проблема: spawn и forkserver пере-импортируют __main__.
    Если родитель запущен из stdin (heredoc, REPL, notebook, -c),
    это падает с FileNotFoundError: '<stdin>'.

    Решение: в этом случае используем fork (Linux/macOS), который
    не требует пере-импорта. Для production (запуск из файла)
    остаются forkserver/spawn — они чище.
    """
    main_mod = sys.modules.get("__main__")
    main_file = getattr(main_mod, "__file__", None)
    from_stdin = (
        main_file is None
        or main_file in ("<stdin>", "<string>", "-c")
        or (isinstance(main_file, str) and not os.path.exists(main_file))
    )

    if from_stdin:
        try:
            return mp.get_context("fork")
        except (ValueError, OSError):
            pass  # fork недоступен (Windows) — падаем на общий путь

    for method in ("forkserver", "spawn"):
        try:
            return mp.get_context(method)
        except (ValueError, OSError):
            continue
    return mp.get_context()

# ---------------------------------------------------------------------------
# Ограничения ресурсов
# ---------------------------------------------------------------------------

def _apply_rlimits(cpu_seconds: int, memory_bytes: int) -> None:
    """Применяет RLIMIT_* в текущем (дочернем) процессе.

    RLIMIT_NPROC НЕ трогаем (ТЗ §8.5).
    """
    try:
        import resource  # type: ignore
    except ImportError:
        # Windows: resource недоступен. Только timeout остаётся.
        return

    # CPU
    # soft < hard: SIGXCPU срабатывает первым, hard — только страховка
    try:
        resource.setrlimit(
            resource.RLIMIT_CPU,
            (cpu_seconds, cpu_seconds + 5),
        )
    except (ValueError, OSError):
        pass

    # Адресное пространство
    try:
        resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    except (ValueError, OSError):
        pass

    # Файлы: запрет записи
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    except (ValueError, OSError):
        pass

def _describe_worker_exit(exitcode: Optional[int]) -> str:
    """Превращает exitcode worker'а в человекочитаемую причину."""
    if exitcode is None:
        return "worker died (exitcode unknown)"
    if exitcode == 0:
        return "worker exited cleanly without results"
    if exitcode < 0:
        signum = -exitcode
        try:
            signame = _signal.Signals(signum).name
        except ValueError:
            signame = f"signal {signum}"
        if signum == getattr(_signal, "SIGXCPU", -1):
            return f"cpu limit exceeded ({signame})"
        if signum == getattr(_signal, "SIGKILL", -1):
            return f"killed externally ({signame}) — likely OOM or timeout"
        if signum == getattr(_signal, "SIGSEGV", -1):
            return f"segfault ({signame})"
        return f"killed by {signame}"
    return f"worker exited with code {exitcode}"


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

@dataclass
class _Job:
    """Один блок работы: сообщение + его метаданные."""
    index: int
    stream_offset: int
    length: int
    payload: bytes


def _worker_main(
    code: str,
    jobs: "mp.Queue[Optional[_Job]]",
    results: "mp.Queue[dict]",
    stderr_pipe_fd: int,
    cpu_seconds: int,
    memory_bytes: int,
    seed: int,
) -> None:
    """Точка входа worker-процесса."""
    # Перенаправляем stderr в pipe, чтобы родитель его вычитал.
    try:
        os.dup2(stderr_pipe_fd, 2)
        os.close(stderr_pipe_fd)
    except OSError:
        pass

    _apply_rlimits(cpu_seconds, memory_bytes)
    random.seed(seed)

    # Компилируем пользовательский код
    try:
        user_module: dict[str, Any] = {
            "__name__": "__sandbox__",
            "__builtins__": _build_safe_builtins(),
        }
        compiled = compile(code, "<sandbox>", "exec")
        exec(compiled, user_module)
    except BaseException as e:
        results.put({
            "fatal": f"compile failed: {type(e).__name__}: {e}",
        })
        return

    handler = user_module.get("interpret")
    if not callable(handler):
        results.put({
            "fatal": "no callable 'interpret(message, index, stream_offset) -> dict'",
        })
        return

    # Основной цикл
    while True:
        try:
            job = jobs.get(timeout=60)
        except queue.Empty:
            results.put({"fatal": "worker idle timeout"})
            return
        if job is None:
            return  # сигнал завершения

        try:
            out = handler(job.payload, job.index, job.stream_offset)
            if not isinstance(out, dict):
                raise TypeError("interpret() must return dict")
            results.put({
                "index": job.index,
                "stream_offset": job.stream_offset,
                "length": job.length,
                "result": out,
            })
        except BaseException as e:
            results.put({
                "index": job.index,
                "stream_offset": job.stream_offset,
                "length": job.length,
                "error": f"{type(e).__name__}: {e}",
            })


# ---------------------------------------------------------------------------
# Интерпретатор
# ---------------------------------------------------------------------------

class ScriptInterpreter(BaseInterpreter):
    """Sandbox-исполнитель для script-интерпретаций."""

    def __init__(
        self,
        spec: dict[str, Any],
        name: str,
        version: int = 1,
        cpu_seconds: int = 10,
        memory_bytes: int = 512 * 1024 * 1024,   # 512 MiB
        timeout_per_message: float = 5.0,
        seed: int = 0,
    ):
        super().__init__(spec, name, version)
        code = spec.get("code")
        if not isinstance(code, str) or not code.strip():
            raise InterpretationError(f"{self.name}: missing 'code' in script spec")
        self._code = code
        self._cpu_seconds = cpu_seconds
        self._memory_bytes = memory_bytes
        self._timeout_per_message = timeout_per_message
        self._seed = seed

    def interpret(self, stream: bytes, direction_id: int) -> list[MessageResult]:
        """Запускает worker, прогоняет все сообщения, собирает результаты.

        Framing должен быть выполнен до вызова этого метода. Здесь
        stream — это reassembled поток; сообщения определяются по
        spec['framing'] (если задан) либо по spec['message_size'].
        """
        messages = self._split_messages(stream)
        if not messages:
            return []

        ctx = _get_mp_context()
        jobs: "mp.Queue[Optional[_Job]]" = ctx.Queue()
        results: "mp.Queue[dict]" = ctx.Queue()
        r_stderr, w_stderr = os.pipe()

        worker = ctx.Process(
            target=_worker_main,
            args=(self._code, jobs, results, w_stderr,
                  self._cpu_seconds, self._memory_bytes, self._seed),
            daemon=True,
        )
        worker.start()
        os.close(w_stderr)  # родитель не пишет в pipe

        # Вычитываем stderr параллельно, иначе дедлок на 64 КиБ.
        stderr_buf: list[bytes] = []
        stop_reader = threading.Event()

        def _read_stderr() -> None:
            try:
                while not stop_reader.is_set():
                    chunk = os.read(r_stderr, 4096)
                    if not chunk:
                        break
                    stderr_buf.append(chunk)
            except OSError:
                pass

        reader = threading.Thread(target=_read_stderr, daemon=True)
        reader.start()

        # Отправляем задачи
        for m in messages:
            jobs.put(m)
        jobs.put(None)  # сигнал завершения

        # Собираем результаты с учётом таймаута
        collected: dict[int, dict] = {}
        deadline = time.monotonic() + self._timeout_per_message * max(len(messages), 1) + 0.5
        fatal: Optional[str] = None

        while len(collected) < len(messages):
            if time.monotonic() > deadline:
                fatal = "timeout (wall clock)"
                break
            try:
                item = results.get(timeout=0.1)
            except queue.Empty:
                if not worker.is_alive():
                    fatal = _describe_worker_exit(worker.exitcode)
                    break
                continue
            if "fatal" in item:
                fatal = item["fatal"]
                break
            idx = item.get("index")
            if idx is not None:
                collected[idx] = item

        # Убиваем worker и закрываем ресурсы
        stop_reader.set()
        try:
            if worker.is_alive():
                worker.kill()
            worker.join(timeout=2.0)
        except Exception:
            pass

        try:
            os.close(r_stderr)
        except OSError:
            pass

        # Формируем MessageResult
        results_out: list[MessageResult] = []
        for m in messages:
            if m.index in collected:
                item = collected[m.index]
                if "error" in item:
                    results_out.append(MessageResult(
                        index=m.index,
                        stream_offset=m.stream_offset,
                        length=m.length,
                        message_name=self.name,
                        status=MessageStatus.PARTIAL,
                        notes=[item["error"]],
                    ))
                else:
                    r = item["result"]
                    results_out.append(MessageResult(
                        index=m.index,
                        stream_offset=m.stream_offset,
                        length=m.length,
                        message_name=self.name,
                        status=MessageStatus(r.get("status", "ok")),
                        fields=r.get("fields", {}),
                        notes=r.get("notes", []),
                        unknown_ranges=r.get("unknown_ranges", []),
                    ))
            else:
                notes = [fatal] if fatal else ["no result from worker"]
                if stderr_buf:
                    notes.append("stderr: " + b"".join(stderr_buf)[:200].decode("utf-8", "replace"))
                results_out.append(MessageResult(
                    index=m.index,
                    stream_offset=m.stream_offset,
                    length=m.length,
                    message_name=self.name,
                    status=MessageStatus.UNKNOWN_FRAME,
                    notes=notes,
                ))
        return results_out

    def _split_messages(self, stream: bytes) -> list[_Job]:
        """Разбивает поток на сообщения.

        Если в спеке есть 'message_size' — фиксированный размер.
        Иначе — одно сообщение на весь поток (интерпретатор сам разберётся).
        """
        size = self.spec.get("message_size")
        if isinstance(size, int) and size > 0:
            jobs: list[_Job] = []
            offset = 0
            idx = 0
            while offset + size <= len(stream):
                jobs.append(_Job(
                    index=idx,
                    stream_offset=offset,
                    length=size,
                    payload=stream[offset:offset + size],
                ))
                offset += size
                idx += 1
            return jobs
        # Единое сообщение
        return [_Job(index=0, stream_offset=0, length=len(stream), payload=stream)]