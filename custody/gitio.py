"""Thin, safe wrappers around the git command line.

Every call passes an argument list, never a shell string, so repository paths,
refs and branch names cannot be interpreted as commands. Refs supplied by a
caller are validated before use.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

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
        raise GitError("unsafe git ref: %r" % (ref,))
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
        raise GitError("git %s timed out after %ss" % (" ".join(args), timeout)) from exc
    return GitResult(completed.returncode, completed.stdout, completed.stderr)


def require_git(repo: Path, args: Sequence[str]) -> str:
    """Run git and return stdout, raising :class:`GitError` on failure."""
    result = run_git(repo, args)
    if not result.ok:
        raise GitError("git %s failed: %s" % (" ".join(args), result.stderr.strip()))
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


def is_clean(repo: Path) -> bool:
    """Return whether the working tree has no uncommitted changes."""
    return not require_git(repo, ["status", "--porcelain"]).strip()


def changed_files(repo: Path, base: str = "HEAD") -> List[str]:
    """Return paths that differ from ``base``, including untracked files."""
    validate_ref(base)
    tracked = require_git(repo, ["diff", "--name-only", base]).split()
    untracked = require_git(repo, ["ls-files", "--others", "--exclude-standard"]).split()
    return sorted(set(tracked) | set(untracked))


def diff(repo: Path, base: str = "HEAD", path: Optional[str] = None) -> str:
    """Return a unified diff against ``base``, optionally limited to ``path``."""
    validate_ref(base)
    args = ["diff", "--unified=3", base]
    if path is not None:
        args.extend(["--", path])
    return require_git(repo, args)


def file_at(repo: Path, ref: str, path: str) -> Optional[str]:
    """Return the contents of ``path`` at ``ref``, or ``None`` if absent."""
    validate_ref(ref)
    result = run_git(repo, ["show", "%s:%s" % (ref, path)])
    return result.stdout if result.ok else None


def create_branch(repo: Path, name: str) -> None:
    """Create and check out a new branch."""
    validate_ref(name)
    require_git(repo, ["checkout", "-b", name])


def commit_all(repo: Path, message: str) -> str:
    """Stage every change and commit it, returning the new SHA."""
    require_git(repo, ["add", "-A"])
    result = run_git(repo, ["commit", "-m", message])
    if not result.ok and "nothing to commit" in (result.stdout + result.stderr):
        raise GitError("nothing to commit")
    if not result.ok:
        raise GitError("commit failed: %s" % result.stderr.strip())
    return head_sha(repo)


def restore_to(repo: Path, sha: str) -> None:
    """Discard every change made since ``sha``, including untracked files.

    This is the harness's auto-revert. It is deliberately total: a remediation
    attempt that fails its gate leaves nothing behind but a ledger entry. The
    caller is responsible for ensuring ``repo`` is a scratch branch.
    """
    validate_ref(sha)
    require_git(repo, ["reset", "--hard", sha])
    require_git(repo, ["clean", "-fd"])
