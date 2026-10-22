"""Ingest Suricata alerts from an eve.json file.

Two modes:
  read_alerts()  -- single pass over an existing file (for replay / eval).
  tail_alerts()  -- follow the file live, yielding new alert records as they
                    are written. Handles the file not existing yet, log
                    rotation (inode change), and partial trailing lines.

We never re-parse the whole file on each poll -- we track our read offset,
which is what lets this keep up with a busy sensor.
"""
from __future__ import annotations

import json
import os
import time
import threading
from typing import Iterator


def read_alerts(path: str) -> Iterator[dict]:
    """Yield every 'alert' record in an eve.json file, one pass."""
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(rec, dict) and rec.get("event_type") == "alert":
                yield rec


def tail_alerts(path: str, poll_interval: float = 0.5,
                from_start: bool = False, stop_event=None) -> Iterator[dict]:
    """Follow eve.json indefinitely, yielding new 'alert' records."""
    stop_event = stop_event or threading.Event()
    while not os.path.exists(path):
        if stop_event.wait(poll_interval):
            return

    f = open(path, "r")
    if not from_start:
        f.seek(0, os.SEEK_END)
    inode = os.fstat(f.fileno()).st_ino
    buf = ""

    try:
        while not stop_event.is_set():
            # Detect rotation: the path now points at a different inode.
            try:
                if os.stat(path).st_ino != inode or os.stat(path).st_size < f.tell():
                    f.close()
                    f = open(path, "r")
                    inode = os.fstat(f.fileno()).st_ino
                    buf = ""
            except FileNotFoundError:
                stop_event.wait(poll_interval)
                continue

            chunk = f.read()
            if not chunk:
                stop_event.wait(poll_interval)
                continue

            buf += chunk
            lines = buf.split("\n")
            buf = lines.pop()  # retain the (possibly incomplete) last line
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict) and rec.get("event_type") == "alert":
                    yield rec
    finally:
        f.close()
