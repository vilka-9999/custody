"""Append-only, hash-chained ledger of agent activity.

Every action an agent takes is recorded as one JSONL entry whose hash covers
both its own content and the hash of the entry before it. Altering or removing
any historical entry invalidates every hash that follows, so the record is
tamper-evident: :func:`verify_chain` recomputes the chain offline and reports
the first entry that does not reconcile.

The ledger is the observability substrate for the whole system. Nothing is
summarised to a human before it is appended here.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
"""Hash that precedes the first entry in a chain."""

_HASH_FIELD = "entry_hash"


class LedgerError(RuntimeError):
    """Raised when a ledger file cannot be read as a ledger at all.

    A line that is not valid JSON, or not a valid entry, is tampering or
    corruption - either way the chain cannot be pronounced intact. Raising a
    typed error lets ``verify`` report a broken chain instead of crashing
    with a traceback that says nothing about custody.
    """


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string with a Z suffix."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_json(payload: dict[str, Any]) -> str:
    """Serialise ``payload`` deterministically.

    Key order, separators and unicode handling are all pinned so that the same
    logical entry always produces the same bytes, and therefore the same hash,
    on any machine.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(data: str) -> str:
    """Return the hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Entry:
    """One recorded action in the proceeding.

    Attributes:
        seq: Zero-based position in the chain.
        ts: UTC timestamp of the moment the entry was created.
        actor: Which component acted, e.g. ``surveyor`` or ``remediator``.
        action: Short verb describing what happened, e.g. ``finding.opened``.
        target: What the action was about, e.g. a finding id or a file path.
        detail: Free-form structured payload specific to the action.
        files_touched: Repository-relative paths written during the action.
        tokens_in: Prompt tokens consumed, or 0 for deterministic work.
        tokens_out: Completion tokens produced, or 0 for deterministic work.
        cost_usd: Model spend attributed to this action.
        verdict: Adjudication result when the actor is the auditor.
        prev_hash: Hash of the preceding entry.
        entry_hash: Hash covering this entry and ``prev_hash``.
    """

    seq: int
    ts: str
    actor: str
    action: str
    target: str = ""
    detail: dict[str, Any] = field(default_factory=dict)
    files_touched: list[str] = field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    verdict: str = ""
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""

    def body(self) -> dict[str, Any]:
        """Return every field except the entry's own hash."""
        return {f.name: getattr(self, f.name) for f in fields(self) if f.name != _HASH_FIELD}

    def compute_hash(self) -> str:
        """Derive this entry's hash from its body and its predecessor."""
        return digest(canonical_json(self.body()))

    def sealed(self) -> Entry:
        """Return a copy of this entry with ``entry_hash`` filled in."""
        data = asdict(self)
        data[_HASH_FIELD] = self.compute_hash()
        return Entry(**data)


@dataclass(frozen=True)
class ChainReport:
    """Result of verifying a ledger file."""

    entries: int
    intact: bool
    broken_at: int | None = None
    reason: str = ""
    expected_entries: int | None = None

    def summary(self) -> str:
        """Return a one-line human summary of the verification."""
        if self.intact:
            return f"chain intact: {self.entries} entries verified"
        if self.broken_at is None:
            return f"chain BROKEN: {self.reason}"
        return f"chain BROKEN at entry {self.broken_at}: {self.reason}"


class Ledger:
    """An append-only JSONL ledger stored at a fixed path.

    The ledger never rewrites history. :meth:`append` seals an entry against
    the current tail and writes one line; there is deliberately no update or
    delete operation.

    A hash chain alone cannot detect truncation of its own tail: dropping the
    last N lines leaves a shorter but perfectly self-consistent prefix, since
    nothing in entry *k* depends on entry *k+1* ever having existed. A
    separate head file records the expected sequence number and tail hash, so
    a truncated ledger disagrees with it. That raises the bar rather than
    closing the hole - an attacker able to write both files can forge a
    consistent history - which is why the ledger directory is integrity-
    critical and refused at the filesystem for any agent under audit.
    """

    def __init__(self, path: Path) -> None:
        """Open (but do not create) a ledger at ``path``."""
        self.path = Path(path)
        self.head_path = self.path.with_name(self.path.name + ".head")
        self._seq = 0
        self._tail = GENESIS_HASH
        if self.path.exists():
            self._resume()

    def _resume(self) -> None:
        """Restore sequence and tail hash from an existing file."""
        last: Entry | None = None
        for entry in self.read():
            last = entry
        if last is not None:
            self._seq = last.seq + 1
            self._tail = last.entry_hash

    @property
    def tail_hash(self) -> str:
        """Hash of the most recent entry, or the genesis hash when empty."""
        return self._tail

    def append(
        self,
        actor: str,
        action: str,
        target: str = "",
        detail: dict[str, Any] | None = None,
        files_touched: Iterable[str] | None = None,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cost_usd: float = 0.0,
        verdict: str = "",
    ) -> Entry:
        """Seal one entry against the current tail and write it to disk."""
        entry = Entry(
            seq=self._seq,
            ts=_utc_now(),
            actor=actor,
            action=action,
            target=target,
            detail=dict(detail or {}),
            files_touched=sorted(files_touched or []),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=round(cost_usd, 6),
            verdict=verdict,
            prev_hash=self._tail,
        ).sealed()
        self._write(entry)
        self._seq = entry.seq + 1
        self._tail = entry.entry_hash
        return entry

    def _write(self, entry: Entry) -> None:
        """Append one serialised entry and update the head marker."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = canonical_json(asdict(entry))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._write_head(entry)

    def _write_head(self, entry: Entry) -> None:
        """Record the expected tail so truncation becomes detectable."""
        _atomic_write(
            self.head_path,
            canonical_json({"seq": entry.seq, "entry_hash": entry.entry_hash}),
        )

    def read_head(self) -> dict[str, Any] | None:
        """Return the recorded head marker, or ``None`` when absent."""
        try:
            raw = self.head_path.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None

    def read(self) -> Iterator[Entry]:
        """Yield every entry in the ledger, oldest first.

        Raises:
            LedgerError: If a line is not a well-formed entry. Malformed
                content is a broken record, not something to skip past.
        """
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for lineno, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    yield Entry(**json.loads(line))
                except (json.JSONDecodeError, TypeError) as exc:
                    raise LedgerError(
                        f"entry at line {lineno} is not a well-formed ledger entry: {exc}"
                    ) from exc

    def total_cost(self) -> float:
        """Return the summed model spend recorded in the ledger."""
        return round(sum(entry.cost_usd for entry in self.read()), 6)

    def verify(self) -> ChainReport:
        """Recompute the hash chain and check it against the head marker."""
        try:
            entries = list(self.read())
        except LedgerError as exc:
            return ChainReport(entries=0, intact=False, reason=str(exc))
        report = verify_chain(entries)
        if not report.intact:
            return report

        head = self.read_head()
        if head is None:
            # A ledger with entries but no marker cannot rule out truncation:
            # dropping the tail *and* the marker file leaves a perfectly
            # self-consistent prefix. An earlier version accepted that as
            # intact, which made deleting one extra file a complete bypass of
            # the truncation check.
            if report.entries == 0:
                return report
            return ChainReport(
                entries=report.entries,
                intact=False,
                reason=(
                    "ledger holds %d entries but its head marker is missing; "
                    "truncation cannot be ruled out" % report.entries
                ),
            )

        expected_seq = head.get("seq")
        expected_hash = head.get("entry_hash")
        if not isinstance(expected_seq, int):
            return ChainReport(
                entries=report.entries, intact=False,
                reason="head marker is malformed; it does not record a sequence number",
            )
        expected_entries = expected_seq + 1

        if report.entries != expected_entries:
            return ChainReport(
                entries=report.entries,
                intact=False,
                reason=(
                    "ledger holds %d entries but the head marker records %d; "
                    "entries were removed from the end"
                    % (report.entries, expected_entries)
                ),
                expected_entries=expected_entries,
            )

        tail_hash = entries[-1].entry_hash if entries else GENESIS_HASH
        if isinstance(expected_hash, str) and expected_hash != tail_hash:
            return ChainReport(
                entries=report.entries,
                intact=False,
                reason=(
                    "the head marker does not match the final entry's seal; "
                    "the tail was rewritten"
                ),
                expected_entries=expected_entries,
            )
        return report


def verify_chain(entries: Iterable[Entry]) -> ChainReport:
    """Walk ``entries`` and confirm every seal and link reconciles.

    Three independent properties are checked for each entry: the sequence
    number increments by exactly one, ``prev_hash`` matches the previous
    entry's seal, and the recorded ``entry_hash`` matches a fresh computation
    over the entry's body.
    """
    expected_prev = GENESIS_HASH
    count = 0

    for expected_seq, entry in enumerate(entries):
        if entry.seq != expected_seq:
            return ChainReport(count, False, entry.seq, f"expected seq {expected_seq}")
        if entry.prev_hash != expected_prev:
            return ChainReport(count, False, entry.seq, "prev_hash does not match preceding entry")
        if entry.entry_hash != entry.compute_hash():
            return ChainReport(count, False, entry.seq, "entry content does not match its seal")
        expected_prev = entry.entry_hash
        count += 1

    return ChainReport(count, True)


def load(path: Path) -> list[Entry]:
    """Read every entry from the ledger file at ``path``."""
    return list(Ledger(path).read())


def _atomic_write(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a temporary file in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=str(path.parent), delete=False
    )
    try:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()
    Path(handle.name).replace(path)
