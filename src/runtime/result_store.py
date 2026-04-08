"""Persistent result store for Agent-G investigations.

SQLite-backed. Meta-agents can query prior investigations by binary hash,
task kind, model, or time range. Results survive process restarts.

Schema
------
``investigations`` table (primary):
  - trace_id         TEXT PRIMARY KEY     # uuid4 hex, 12 chars
  - binary_path      TEXT                  # absolute path at run time
  - binary_sha256    TEXT INDEXED          # content hash, stable across renames
  - binary_name      TEXT                  # display name the model saw
  - task_kind        TEXT INDEXED          # "vuln" / "malware_triage" / etc
  - provider         TEXT                  # "anthropic" / "google" / ...
  - model_id         TEXT                  # "claude-opus-4-6" etc
  - prompt_version   TEXT                  # "v1" / "v2" — from prompt_library
  - verdict          TEXT                  # "VULNERABLE"/"NOT_VULNERABLE"/...
  - exit_reason      TEXT                  # "complete"/"max_iter"/...
  - started_at       TEXT INDEXED          # ISO-8601 UTC
  - finished_at      TEXT                  # ISO-8601 UTC
  - elapsed_s        REAL                  # wall-clock duration
  - iterations       INTEGER
  - tool_calls       INTEGER
  - input_tokens     INTEGER
  - output_tokens    INTEGER
  - cost_usd         REAL
  - final_text       TEXT                  # verdict block / summary
  - report_text      TEXT                  # full free-text report (may be large)
  - runs_dir         TEXT                  # filesystem path to per-trace artifacts
  - metadata_json    TEXT                  # free-form JSON for extra fields

``findings`` table (1:N):
  - trace_id         TEXT (FK)
  - finding_idx      INTEGER
  - cwe              TEXT
  - severity         TEXT                  # "critical"/"high"/...
  - address          TEXT                  # function / offset
  - description      TEXT
  - evidence         TEXT

WAL mode is enabled for reader/writer concurrency. The store is
thread-safe within a single process via a per-connection lock; cross-
process writers work via SQLite's file lock.

Lookups
-------
  - ``record(...)`` inserts one investigation
  - ``get(trace_id)`` returns one row
  - ``find_by_binary(binary_sha256)`` returns all runs against a binary
  - ``find_latest(binary_sha256, task_kind, model_id)`` for cache hits
  - ``list_recent(limit=50)`` for meta-agent browsing
  - ``add_finding(...)`` appends a structured finding
  - ``findings(trace_id)`` returns all findings for a run
"""
from __future__ import annotations
import json
import logging
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger("agent-g.result_store")


SCHEMA = r"""
CREATE TABLE IF NOT EXISTS investigations (
    trace_id        TEXT PRIMARY KEY,
    binary_path     TEXT,
    binary_sha256   TEXT,
    binary_name     TEXT,
    task_kind       TEXT,
    provider        TEXT,
    model_id        TEXT,
    prompt_version  TEXT,
    verdict         TEXT,
    exit_reason     TEXT,
    started_at      TEXT,
    finished_at     TEXT,
    elapsed_s       REAL,
    iterations      INTEGER,
    tool_calls      INTEGER,
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    cost_usd        REAL,
    final_text      TEXT,
    report_text     TEXT,
    runs_dir        TEXT,
    metadata_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_investigations_sha256
    ON investigations(binary_sha256);
CREATE INDEX IF NOT EXISTS idx_investigations_started_at
    ON investigations(started_at);
CREATE INDEX IF NOT EXISTS idx_investigations_task_model
    ON investigations(task_kind, model_id);

CREATE TABLE IF NOT EXISTS findings (
    trace_id        TEXT,
    finding_idx     INTEGER,
    cwe             TEXT,
    severity        TEXT,
    address         TEXT,
    description     TEXT,
    evidence        TEXT,
    PRIMARY KEY (trace_id, finding_idx),
    FOREIGN KEY (trace_id) REFERENCES investigations(trace_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_findings_cwe ON findings(cwe);
"""


@dataclass
class Investigation:
    """A single Agent-G investigation record."""
    trace_id: str
    binary_path: str = ""
    binary_sha256: str = ""
    binary_name: str = ""
    task_kind: str = ""
    provider: str = ""
    model_id: str = ""
    prompt_version: str = "v0"
    verdict: str = ""
    exit_reason: str = ""
    started_at: str = ""
    finished_at: str = ""
    elapsed_s: float = 0.0
    iterations: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    final_text: str = ""
    report_text: str = ""
    runs_dir: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_row(self) -> tuple:
        return (
            self.trace_id, self.binary_path, self.binary_sha256, self.binary_name,
            self.task_kind, self.provider, self.model_id, self.prompt_version,
            self.verdict, self.exit_reason, self.started_at, self.finished_at,
            self.elapsed_s, self.iterations, self.tool_calls,
            self.input_tokens, self.output_tokens, self.cost_usd,
            self.final_text, self.report_text, self.runs_dir,
            json.dumps(self.metadata or {}, default=str),
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Investigation":
        d = dict(row)
        md = d.pop("metadata_json", "") or "{}"
        try:
            d["metadata"] = json.loads(md)
        except Exception:
            d["metadata"] = {}
        return cls(**d)


@dataclass
class Finding:
    trace_id: str
    finding_idx: int
    cwe: str = ""
    severity: str = ""
    address: str = ""
    description: str = ""
    evidence: str = ""


# ── Store ────────────────────────────────────────────────────────────

class ResultStore:
    """SQLite-backed persistent store for investigations.

    Usage::

        store = ResultStore(Path("runs/results.sqlite"))
        store.record(investigation)

        hit = store.find_latest(sha256, task_kind="vuln", model_id="claude-opus-4-6")
        if hit and (time.time() - iso_to_ts(hit.finished_at)) < 86400:
            return hit  # cached verdict within 1 day

    Thread-safe within a single process. Cross-process writes are
    serialized by SQLite's file lock; readers don't block thanks to WAL.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            str(self.db_path),
            isolation_level=None,  # autocommit; we still BEGIN/COMMIT on writes
            timeout=10.0,
        )
        conn.row_factory = sqlite3.Row
        # WAL enables concurrent readers while a writer has the DB
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _cursor(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            conn = self._connect()
            try:
                yield conn.cursor()
                conn.commit()
            finally:
                conn.close()

    # ── Writes ──

    def record(self, inv: Investigation) -> None:
        """Insert or upsert one investigation by trace_id."""
        if not inv.finished_at:
            inv.finished_at = datetime.now(timezone.utc).isoformat()
        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO investigations VALUES
                   (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                inv.to_row(),
            )
        logger.info(
            "recorded investigation trace_id=%s verdict=%s model=%s sha256=%s",
            inv.trace_id, inv.verdict, inv.model_id,
            (inv.binary_sha256 or "")[:12],
        )

    def add_finding(self, finding: Finding) -> None:
        with self._cursor() as cur:
            cur.execute(
                """INSERT OR REPLACE INTO findings
                   (trace_id, finding_idx, cwe, severity, address, description, evidence)
                   VALUES (?,?,?,?,?,?,?)""",
                (finding.trace_id, finding.finding_idx, finding.cwe,
                 finding.severity, finding.address, finding.description, finding.evidence),
            )

    def delete(self, trace_id: str) -> None:
        with self._cursor() as cur:
            cur.execute("DELETE FROM findings WHERE trace_id = ?", (trace_id,))
            cur.execute("DELETE FROM investigations WHERE trace_id = ?", (trace_id,))

    # ── Reads ──

    def get(self, trace_id: str) -> Optional[Investigation]:
        with self._cursor() as cur:
            cur.execute("SELECT * FROM investigations WHERE trace_id = ?", (trace_id,))
            row = cur.fetchone()
            return Investigation.from_row(row) if row else None

    def find_by_binary(
        self, binary_sha256: str, *, limit: int = 100,
    ) -> List[Investigation]:
        with self._cursor() as cur:
            cur.execute(
                """SELECT * FROM investigations
                   WHERE binary_sha256 = ?
                   ORDER BY started_at DESC
                   LIMIT ?""",
                (binary_sha256, limit),
            )
            return [Investigation.from_row(r) for r in cur.fetchall()]

    def find_latest(
        self,
        binary_sha256: str,
        *,
        task_kind: Optional[str] = None,
        model_id: Optional[str] = None,
        prompt_version: Optional[str] = None,
    ) -> Optional[Investigation]:
        """Return the most recent run that matches the given keys.

        Useful as a cache: `if store.find_latest(sha, task_kind, model) and
        fresh: return it`. Nones in keys mean "any".
        """
        sql = "SELECT * FROM investigations WHERE binary_sha256 = ?"
        params: List[Any] = [binary_sha256]
        if task_kind is not None:
            sql += " AND task_kind = ?"; params.append(task_kind)
        if model_id is not None:
            sql += " AND model_id = ?"; params.append(model_id)
        if prompt_version is not None:
            sql += " AND prompt_version = ?"; params.append(prompt_version)
        sql += " ORDER BY started_at DESC LIMIT 1"
        with self._cursor() as cur:
            cur.execute(sql, params)
            row = cur.fetchone()
            return Investigation.from_row(row) if row else None

    def list_recent(self, limit: int = 50) -> List[Investigation]:
        with self._cursor() as cur:
            cur.execute(
                "SELECT * FROM investigations ORDER BY started_at DESC LIMIT ?",
                (limit,),
            )
            return [Investigation.from_row(r) for r in cur.fetchall()]

    def findings(self, trace_id: str) -> List[Finding]:
        with self._cursor() as cur:
            cur.execute(
                """SELECT trace_id, finding_idx, cwe, severity, address,
                          description, evidence
                   FROM findings WHERE trace_id = ? ORDER BY finding_idx""",
                (trace_id,),
            )
            return [Finding(**dict(r)) for r in cur.fetchall()]

    def count(self) -> int:
        with self._cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM investigations")
            return cur.fetchone()[0]


def record_from_provenance(
    store: ResultStore,
    bundle,  # ProvenanceBundle
    *,
    task_kind: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Investigation:
    """Convenience: convert a ``ProvenanceBundle`` into an ``Investigation``
    and persist it. Use this to close out a run with a single call."""
    inv = Investigation(
        trace_id=bundle.trace_id,
        binary_path=bundle.binary_path,
        binary_sha256=bundle.binary_sha256,
        binary_name=Path(bundle.binary_path).name if bundle.binary_path else "",
        task_kind=task_kind,
        provider=bundle.model_provider,
        model_id=bundle.model_id,
        prompt_version=bundle.prompt_version,
        verdict=bundle.verdict,
        exit_reason=bundle.exit_reason,
        started_at=bundle.started_at,
        finished_at=bundle.finished_at,
        elapsed_s=bundle.elapsed_s,
        iterations=bundle.iterations,
        tool_calls=bundle.tool_calls,
        input_tokens=bundle.input_tokens,
        output_tokens=bundle.output_tokens,
        cost_usd=bundle.cost_usd,
        final_text=bundle.final_text,
        runs_dir="",
        metadata=metadata or {},
    )
    store.record(inv)
    return inv
