"""LogHawk web service.

    uvicorn loghawk.api:app --reload   -> http://127.0.0.1:8000
"""
from __future__ import annotations

import tempfile
import threading
from collections import Counter
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse

from .generator import LogGen
from .parsers import Event, parse_file, parse_lines
from .pipeline import analyse_events, load_ueba, train_ueba
from .rules import SEVERITY_WEIGHT, load_rules
from .search import search

app = FastAPI(title="LogHawk", version="1.0.0", description="SIEM-lite: log analysis, detection rules, UEBA and incident correlation")
TEMPLATE = Path(__file__).parent / "templates" / "index.html"
MAX_UPLOAD = 100 * 1024 * 1024


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.events: list[Event] = []
        self.alerts: list = []
        self.incidents: list = []
        self.stats: dict = {}
        self.ueba = load_ueba()

    def set(self, events, ueba_from=None):
        res = analyse_events(events, self.ueba, ueba_from=ueba_from)
        with self.lock:
            self.events, self.alerts, self.incidents, self.stats = res.events, res.alerts, res.incidents, res.stats
        return res.stats


S = State()


@app.get("/", response_class=HTMLResponse)
def index():
    return TEMPLATE.read_text(encoding="utf-8")


@app.post("/api/demo")
def demo(seed: int = 1):
    with tempfile.TemporaryDirectory() as d:
        g = LogGen(seed=seed); g.write(d)
        events = [e for f in ("auth.log", "ufw.log", "access.log", "windows_security.jsonl") for e in parse_file(str(Path(d) / f))]
    S.ueba = train_ueba(events, until=g.attack_start, tz_offset_h=5.5)
    return S.set(events, ueba_from=g.attack_start)


@app.post("/api/ingest")
async def ingest(files: list[UploadFile] = File(...), append: bool = False):
    events: list[Event] = list(S.events) if append else []
    for f in files:
        data = await f.read()
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, f"{f.filename} is larger than 100 MB")
        events += parse_lines(data.decode("utf-8", errors="replace").splitlines())
    if not events:
        raise HTTPException(400, "no recognised log lines (supported: auth.log/secure, nginx/apache access, UFW/iptables, Windows JSON)")
    return S.set(events)


@app.post("/api/ueba/train")
def ueba_train():
    if not S.events:
        raise HTTPException(400, "ingest baseline logs first")
    try:
        S.ueba = train_ueba(S.events, tz_offset_h=5.5)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"ok": True, "users": len(S.ueba.user_mean)}


@app.get("/api/stats")
def stats():
    sev = Counter(a.severity for a in S.alerts)
    return S.stats | {"by_severity": sev, "by_rule": Counter(a.title for a in S.alerts).most_common(10),
                      "by_tactic": Counter(a.tactic for a in S.alerts if a.tactic),
                      "ueba_trained": bool(S.ueba and S.ueba.trained)}


@app.get("/api/incidents")
def incidents():
    return [{k: v for k, v in i.to_dict().items() if k != "alerts"} | {"alert_count": len(i.alerts)} for i in S.incidents]


@app.get("/api/incidents/{iid}")
def incident(iid: int):
    for i in S.incidents:
        if i.id == iid:
            return i.to_dict()
    raise HTTPException(404, "incident not found")


@app.get("/api/alerts")
def alerts(severity: str | None = None, rule: str | None = None, limit: int = 500):
    out = [a.to_dict() for a in S.alerts
           if (not severity or a.severity == severity) and (not rule or a.rule_id == rule)]
    return sorted(out, key=lambda a: (-SEVERITY_WEIGHT[a["severity"]], -a["ts"]))[:limit]


@app.get("/api/search")
def do_search(q: str = "", limit: int = 200):
    total, hits = search(S.events, q, min(limit, 1000))
    return {"total": total, "events": [e.to_dict() for e in hits]}


@app.get("/api/coverage")
def coverage():
    """MITRE ATT&CK coverage of the loaded rules, including gaps."""
    from .coverage import compute
    return compute()


@app.get("/api/coverage/navigator")
def coverage_navigator():
    """ATT&CK Navigator layer for the loaded rules (upload it at mitre-attack.github.io/attack-navigator)."""
    from .coverage import compute, navigator_layer
    return navigator_layer(compute())


@app.get("/api/rules")
def rules():
    return [{"id": r.id, "title": r.title, "type": r.type, "severity": r.severity, "mitre": r.mitre,
             "description": r.description, "threshold": r.threshold if r.type == "threshold" else None,
             "window": r.window if r.type != "single" else None} for r in load_rules()]


@app.get("/api/export")
def export():
    return JSONResponse({"stats": S.stats, "incidents": [i.to_dict() for i in S.incidents]},
                        headers={"Content-Disposition": "attachment; filename=loghawk_report.json"})
