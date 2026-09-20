"""Thin, safe wrappers around the git command line.

Every call passes an argument list, never a shell string, so repository paths,
refs and branch names cannot be interpreted as commands. Refs supplied by a
caller are validated before use.
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

SAFE_REF = re.compile(r"^[A-Za-z0-9._/\-]{1,255}$")
"""Refs and branch names must match this to be passed to git."""

DEFAULT_TIMEOUT = 120
"""Seconds any single git invocation may run before it is killed."""


class GitError(RuntimeError):
    """Raised when a git invocation fails or is rejected before running."""


@dataclass(frozen=True)
class GitResult:
    """Outcome of one git invocation."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        """Return whether git exited successfully."""
        return self.returncode == 0


def validate_ref(ref: str) -> str:
    """Return ``ref`` if it is a safe git ref, else raise :class:`GitError`.

    Refs arrive from command-line arguments and configuration files, so they
    are untrusted input even though they are not user-facing.
    """
    if not SAFE_REF.match(ref) or ".." in ref or ref.startswith("-"):
        raise GitError(f"unsafe git ref: {ref!r}")
    return ref


def run_git(repo: Path, args: Sequence[str], timeout: int = DEFAULT_TIMEOUT) -> GitResult:
    """Run one git command inside ``repo`` and capture its output."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError("git {} timed out after {}s".format(" ".join(args), timeout)) from exc
    return GitResult(completed.returncode, completed.stdout, completed.stderr)


def require_git(repo: Path, args: Sequence[str]) -> str:
    """Run git and return stdout, raising :class:`GitError` on failure."""
    result = run_git(repo, args)
    if not result.ok:
        raise GitError("git {} failed: {}".format(" ".join(args), result.stderr.strip()))
    return result.stdout


def is_repo(repo: Path) -> bool:
    """Return whether ``repo`` is inside a git working tree."""
    return run_git(repo, ["rev-parse", "--is-inside-work-tree"]).ok


def current_branch(repo: Path) -> str:
    """Return the checked-out branch name."""
    return require_git(repo, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()


def head_sha(repo: Path) -> str:
    """Return the full SHA of HEAD."""
    return require_git(repo, ["rev-parse", "HEAD"]).strip()


def is_clean(repo: Path, ignore: Sequence[str] = (".custody",)) -> bool:
    """Return whether the working tree has no uncommitted changes.

    Paths under ``ignore`` do not count. Custody writes its ledger inside the
    repository it is auditing, and its own artifact must not be mistaken for
    the operator's uncommitted work - otherwise merely surveying a repository
    would make it ineligible to be hardened.
    """
    return not dirty_paths(repo, ignore)


def dirty_paths(repo: Path, ignore: Sequence[str] = (".custody",)) -> list[str]:
    """Return the uncommitted paths that are not excluded by ``ignore``."""
    prefixes = tuple(p.rstrip("/") + "/" for p in ignore)
    names = tuple(p.rstrip("/") for p in ignore)
    found: list[str] = []
    for line in require_git(repo, ["status", "--porcelain"]).splitlines():
        entry = line[3:].strip().strip('"')
        if not entry:
            continue
        if entry.startswith(prefixes) or entry in names:
            continue
        found.append(entry)
    return found


def changed_files(repo: Path, base: str = "HEAD") -> list[str]:
    """Return paths that differ from ``base``, including untracked files.

    Output is NUL-delimited (``-z``), never whitespace-split: a path with a
    space in it would otherwise fragment into two phantom paths, and the
    auditor's before/after capture would read the wrong files.
    """
    validate_ref(base)
    tracked = require_git(repo, ["diff", "--name-only", "-z", base]).split("\0")
    untracked = require_git(repo, ["ls-files", "--others", "--exclude-standard", "-z"]).split("\0")
    return sorted({path for path in (*tracked, *untracked) if path})


def diff(repo: Path, base: str = "HEAD", path: str | None = None) -> str:
    """Return a unified diff against ``base``, optionally limited to ``path``."""
    validate_ref(base)
    args = ["diff", "--unified=3", base]
    if path is not None:
        args.extend(["--", path])
    return require_git(repo, args)


def file_at(repo: Path, ref: str, path: str) -> str | None:
    """Return the contents of ``path`` at ``ref``, or ``None`` if absent."""
    validate_ref(ref)
    result = run_git(repo, ["show", f"{ref}:{path}"])
    return result.stdout if result.ok else None


def create_branch(repo: Path, name: str) -> None:
    """Create and check out a new branch."""
    validate_ref(name)
    require_git(repo, ["checkout", "-b", name])


def commit_all(repo: Path, message: str, exclude: Sequence[str] = (".custody",)) -> str:
    """Stage every change and commit it, returning the new SHA.

    Custody's own ledger lives inside the repository but is not part of the
    work being committed, so it is excluded from the index. A tool that writes
    its own bookkeeping into the subject's history has changed the subject.
    """
    pathspec = ["."] + [f":(exclude){pattern}" for pattern in exclude]
    require_git(repo, ["add", "-A", "--", *pathspec])
    result = run_git(repo, ["commit", "-m", message])
    if not result.ok and "nothing to commit" in (result.stdout + result.stderr):
        raise GitError("nothing to commit")
    if not result.ok:
        raise GitError(f"commit failed: {result.stderr.strip()}")
    return head_sha(repo)


def restore_to(repo: Path, sha: str, preserve: Sequence[str] = (".custody",)) -> None:
    """Discard every change made since ``sha``, including untracked files.

    This is the harness's auto-revert. It is deliberately total, with one
    exception: paths in ``preserve`` survive. The ledger is untracked and
    lives inside the repository, so a total clean would delete the record of
    the very attempt being reverted - and an empty chain verifies as intact,
    which would make a destroyed audit trail look like a clean one.

    The caller is responsible for ensuring ``repo`` is a scratch branch.
    """
    validate_ref(sha)
    require_git(repo, ["reset", "--hard", sha])
    args = ["clean", "-fd"]
    for pattern in preserve:
        args.extend(["-e", pattern])
    require_git(repo, args)
