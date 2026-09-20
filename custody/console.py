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
from typing import Dict, List, Tuple

from custody.ledger import Entry, Ledger

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


def summarise(entries: List[Entry]) -> Dict[str, object]:
    """Return headline counts derived only from recorded entries."""
    rulings: Dict[str, int] = {}
    files: set = set()
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


def render(ledger: Ledger) -> str:
    """Render the whole ledger as one self-contained HTML page."""
    entries = list(ledger.read())
    report = ledger.verify()
    stats = summarise(entries)

    chain = (
        '<div class="chain ok">Chain intact &mdash; %d entries verified</div>' % report.entries
        if report.intact
        else '<div class="chain bad">CHAIN BROKEN at entry %s &mdash; %s</div>'
        % (_esc(report.broken_at), _esc(report.reason))
    )

    tiles = [
        ("%d" % stats["entries"], "ledger entries"),
        ("%d" % stats["actors"], "actors"),
        ("%d" % stats["files"], "files touched"),
        ("$%.4f" % stats["spend"], "attributed spend"),
    ]
    for ruling, count in sorted(stats["rulings"].items()):
        tiles.append(("%d" % count, ruling.replace("_", " ").lower()))
    tile_html = "".join(
        '<div class="stat"><b>%s</b><span>%s</span></div>' % (_esc(v), _esc(label))
        for v, label in tiles
    )

    rows = []
    for entry in reversed(entries):
        verdict = (
            '<span class="v %s">%s</span>'
            % (RULING_CLASS.get(entry.verdict, ""), _esc(entry.verdict))
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
                "$%.4f" % entry.cost_usd if entry.cost_usd else "",
                _esc(touched[:70]),
            )
        )

    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        "<title>Custody</title><style>%s</style></head><body><div class=wrap>"
        "<h1>Custody</h1>"
        '<p class="sub">Chain of custody for machine-written code. '
        "This view renders the ledger; it does not recompute any verdict.</p>"
        "%s<div class=stats>%s</div>"
        "<table><thead><tr><th>#</th><th>actor</th><th>action</th><th>target</th>"
        "<th>ruling</th><th class=hide-sm>cost</th><th class=hide-sm>files</th>"
        "</tr></thead><tbody>%s</tbody></table>"
        "</div></body></html>"
        % (STYLE, chain, tile_html, "".join(rows) or "<tr><td colspan=7>No entries yet.</td></tr>")
    )


class ConsoleHandler(BaseHTTPRequestHandler):
    """Serves the console page and a JSON view of the ledger."""

    ledger_path: Path = Path(".custody/ledger.jsonl")

    def do_GET(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        """Serve the dashboard, the JSON feed, or a 404."""
        ledger = Ledger(self.ledger_path)
        if self.path.startswith("/ledger.json"):
            report = ledger.verify()
            body = json.dumps(
                {
                    "intact": report.intact,
                    "broken_at": report.broken_at,
                    "entries": [
                        dict(entry.body(), entry_hash=entry.entry_hash)
                        for entry in ledger.read()
                    ],
                },
                indent=2, sort_keys=True,
            ).encode("utf-8")
            self._send(body, "application/json")
        elif self.path in ("/", "/index.html"):
            self._send(render(ledger).encode("utf-8"), "text/html; charset=utf-8")
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

    def log_message(self, fmt: str, *args: object) -> None:
        """Suppress per-request logging, which is noise during a demo."""
        return


def serve(ledger_path: Path, port: int = DEFAULT_PORT) -> None:
    """Serve the console on localhost until interrupted."""
    ConsoleHandler.ledger_path = Path(ledger_path)
    server = HTTPServer(("127.0.0.1", port), ConsoleHandler)
    print("Custody console: http://127.0.0.1:%d" % port)
    print("Reading %s (press Ctrl-C to stop)" % ledger_path)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        server.server_close()
