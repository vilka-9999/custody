"""A read-only web view of the ledger, served from the standard library.

The console renders what the ledger records and nothing else. It never
recomputes a verdict, never hides an entry, and shows the chain verification
result at the top of every page, so a page that looks clean while the chain is
broken is not a state this view can reach.
"""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from custody.ledger import ChainReport, Entry, Ledger, LedgerError

ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "[::1]"})
"""Host headers the console answers.

The server binds to loopback, but a malicious page can point a hostname it
controls at 127.0.0.1 and read the ledger cross-origin - DNS rebinding.
A request whose Host header is not a loopback name did not come from the
operator's own browser bar and is refused.
"""


def _host_allowed(host: str) -> bool:
    """Return whether a request's Host header names this machine's loopback."""
    name = host.strip().lower()
    name = "[::1]" if name.startswith("[::1]") else name.split(":", 1)[0]
    return name in ALLOWED_HOSTS


def _read_safely(ledger: Ledger) -> tuple[list[Entry], ChainReport]:
    """Read the ledger, reporting a malformed file as a broken chain.

    A corrupt line used to crash the request handler, which made that class
    of tampering render the console unreachable instead of rendering the
    broken banner - the one page state this view must always be able to show.
    """
    try:
        entries = list(ledger.read())
    except LedgerError as exc:
        return [], ChainReport(entries=0, intact=False, reason=str(exc))
    return entries, ledger.verify()

DEFAULT_PORT = 8765

RULING_CLASS = {
    "PROVEN": "proven",
    "NOT_OBSERVED": "not-observed",
    "INSUFFICIENT_EVIDENCE": "insufficient",
    "REJECTED": "rejected",
}

STYLE = """
:root{--bg:#fbfbfa;--fg:#1a1a18;--dim:#6b6b66;--line:#e2e2dd;--card:#fff;
--proven:#1f7a4d;--rejected:#b3261e;--not-observed:#8a6d1f;--insufficient:#5a5a70}
@media (prefers-color-scheme:dark){:root{--bg:#16161a;--fg:#e8e8e4;--dim:#9a9a94;
--line:#2c2c32;--card:#1e1e23;--proven:#4ec98a;--rejected:#ff8a80;
--not-observed:#e0c068;--insufficient:#a0a0c0}}
*{box-sizing:border-box}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1040px;margin:0 auto}
h1{font-size:20px;margin:0 0 2px}
.sub{color:var(--dim);font-size:13px;margin-bottom:20px}
.chain{padding:10px 14px;border-radius:8px;font-weight:600;margin-bottom:20px;
border:1px solid var(--line);background:var(--card)}
.ok{color:var(--proven)} .bad{color:var(--rejected)}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:22px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;
padding:10px 14px;min-width:120px;flex:1 1 120px}
.stat b{display:block;font-size:19px;font-variant-numeric:tabular-nums}
.stat span{color:var(--dim);font-size:12px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:8px 11px;text-align:left;border-bottom:1px solid var(--line);
font-size:13px;vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;
letter-spacing:.04em}
tr:last-child td{border-bottom:none}
code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.v{font-weight:700;font-size:12px}
.proven{color:var(--proven)} .rejected{color:var(--rejected)}
.not-observed{color:var(--not-observed)} .insufficient{color:var(--insufficient)}
.num{font-variant-numeric:tabular-nums;white-space:nowrap}
@media(max-width:700px){.hide-sm{display:none}}
"""


def _esc(value: object) -> str:
    """Escape a value for safe insertion into HTML."""
    return html.escape(str(value), quote=True)


def summarise(entries: list[Entry]) -> dict[str, Any]:
    """Return headline counts derived only from recorded entries."""
    rulings: dict[str, int] = {}
    files: set[str] = set()
    for entry in entries:
        if entry.verdict:
            rulings[entry.verdict] = rulings.get(entry.verdict, 0) + 1
        files.update(entry.files_touched)
    return {
        "entries": len(entries),
        "rulings": rulings,
        "files": len(files),
        "spend": round(sum(e.cost_usd for e in entries), 6),
        "actors": len({e.actor for e in entries}),
    }


def _open_ledger(path: Path) -> Ledger | ChainReport:
    """Open the ledger, or return the broken-chain report it deserves.

    Opening resumes from the existing file, so a corrupt ledger raises during
    construction; the console must survive that and say so on the page.
    """
    try:
        return Ledger(path)
    except LedgerError as exc:
        return ChainReport(entries=0, intact=False, reason=str(exc))


def _chain_banner(report: ChainReport) -> str:
    """Render the verification banner for the top of the page."""
    if report.intact:
        return (
            '<div class="chain ok">Chain intact &mdash; '
            f"{report.entries} entries verified</div>"
        )
    where = f"at entry {report.broken_at} " if report.broken_at is not None else ""
    return f'<div class="chain bad">CHAIN BROKEN {_esc(where)}&mdash; {_esc(report.reason)}</div>'


def render_broken(report: ChainReport) -> str:
    """Render the one page state that must always be reachable."""
    chain = _chain_banner(report)
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>Custody</title><style>{STYLE}</style></head><body><div class=wrap>"
        "<h1>Custody</h1>"
        '<p class="sub">Chain of custody for machine-written code. '
        "This view renders the ledger; it does not recompute any verdict.</p>"
        f"{chain}</div></body></html>"
    )


def render(ledger: Ledger) -> str:
    """Render the whole ledger as one self-contained HTML page."""
    entries, report = _read_safely(ledger)
    stats = summarise(entries)
    chain = _chain_banner(report)

    tiles = [
        ("%d" % stats["entries"], "ledger entries"),
        ("%d" % stats["actors"], "actors"),
        ("%d" % stats["files"], "files touched"),
        ("${:.4f}".format(stats["spend"]), "attributed spend"),
    ]
    for ruling, count in sorted(stats["rulings"].items()):
        tiles.append(("%d" % count, ruling.replace("_", " ").lower()))
    tile_html = "".join(
        f'<div class="stat"><b>{_esc(v)}</b><span>{_esc(label)}</span></div>'
        for v, label in tiles
    )

    rows = []
    for entry in reversed(entries):
        verdict = (
            '<span class="v {}">{}</span>'.format(
                RULING_CLASS.get(entry.verdict, ""), _esc(entry.verdict)
            )
            if entry.verdict
            else ""
        )
        touched = ", ".join(entry.files_touched)
        rows.append(
            "<tr><td class=num>%d</td><td><code>%s</code></td><td>%s</td>"
            "<td><code>%s</code></td><td>%s</td>"
            '<td class="num hide-sm">%s</td>'
            '<td class="hide-sm"><code>%s</code></td></tr>'
            % (
                entry.seq, _esc(entry.actor), _esc(entry.action), _esc(entry.target),
                verdict,
                f"${entry.cost_usd:.4f}" if entry.cost_usd else "",
                _esc(touched[:70]),
            )
        )

    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        "<title>Custody</title><style>{}</style></head><body><div class=wrap>"
        "<h1>Custody</h1>"
        '<p class="sub">Chain of custody for machine-written code. '
        "This view renders the ledger; it does not recompute any verdict.</p>"
        "{}<div class=stats>{}</div>"
        "<table><thead><tr><th>#</th><th>actor</th><th>action</th><th>target</th>"
        "<th>ruling</th><th class=hide-sm>cost</th><th class=hide-sm>files</th>"
        "</tr></thead><tbody>{}</tbody></table>"
        "</div></body></html>".format(
            STYLE, chain, tile_html,
            "".join(rows) or "<tr><td colspan=7>No entries yet.</td></tr>",
        )
    )


class ConsoleHandler(BaseHTTPRequestHandler):
    """Serves the console page and a JSON view of the ledger."""

    ledger_path: Path = Path(".custody/ledger.jsonl")

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        """Serve the dashboard, the JSON feed, or a 404."""
        if not _host_allowed(self.headers.get("Host", "")):
            self.send_error(403, "console answers loopback host names only")
            return
        ledger = _open_ledger(self.ledger_path)
        if self.path.startswith("/ledger.json"):
            entries: list[Entry] = []
            if isinstance(ledger, ChainReport):
                report = ledger
            else:
                entries, report = _read_safely(ledger)
            body = json.dumps(
                {
                    "intact": report.intact,
                    "broken_at": report.broken_at,
                    "reason": report.reason,
                    "entries": [
                        dict(entry.body(), entry_hash=entry.entry_hash) for entry in entries
                    ],
                },
                indent=2, sort_keys=True,
            ).encode("utf-8")
            self._send(body, "application/json")
        elif self.path in ("/", "/index.html"):
            page = (
                render_broken(ledger) if isinstance(ledger, ChainReport)
                else render(ledger)
            )
            self._send(page.encode("utf-8"), "text/html; charset=utf-8")
        else:
            self.send_error(404)

    def _send(self, body: bytes, content_type: str) -> None:
        """Write one response with no-cache headers."""
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _fmt: str, *_args: object) -> None:
        """Suppress per-request logging, which is noise during a demo."""
        return


def serve(ledger_path: Path, port: int = DEFAULT_PORT) -> None:
    """Serve the console on localhost until interrupted."""
    ConsoleHandler.ledger_path = Path(ledger_path)
    server = HTTPServer(("127.0.0.1", port), ConsoleHandler)
    print("Custody console: http://127.0.0.1:%d" % port)
    print(f"Reading {ledger_path} (press Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
