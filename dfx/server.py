"""Local web GUI server (127.0.0.1 only)."""
from __future__ import annotations

import datetime as _dt
import json
import mimetypes
import os
import secrets
import string
import sys
import tempfile
import threading
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote

from . import APP_NAME, __version__, DEFAULT_PORT
from .source import open_source, hash_source, list_physical_drives, SourceError
from .carve import Carver, CarveOptions, SignatureLibrary, SignatureError, check, normalize
from .report import build_report

WEB = Path(__file__).resolve().parent / "web"
if getattr(sys, "frozen", False):  # PyInstaller
    WEB = Path(sys._MEIPASS) / "dfx" / "web"  # type: ignore[attr-defined]


def config_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home() / ".config")
    d = Path(base) / "DFX"
    d.mkdir(parents=True, exist_ok=True)
    return d


def utc() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class App:
    def __init__(self):
        self.cfg = config_dir()
        self.lib = SignatureLibrary(self.cfg / "signatures")
        self.case: dict = {}
        self.source: dict = {}
        self.evidence_hash: dict = {}
        self.job = {"type": None, "running": False, "progress": {}, "log": [], "result": None, "error": None}
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self.token = secrets.token_urlsafe(24)
        self._load_settings()

    # ---------------------------------------------------------------- settings
    def _load_settings(self):
        p = self.cfg / "settings.json"
        try:
            s = json.loads(p.read_text(encoding="utf-8"))
            if s.get("last_case") and Path(s["last_case"], "case.json").exists():
                self.open_case({"folder": s["last_case"]}, log=False)
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    def _save_settings(self):
        (self.cfg / "settings.json").write_text(
            json.dumps({"last_case": self.case.get("folder", "")}, indent=2), encoding="utf-8")

    # ---------------------------------------------------------------- case
    def case_log(self, msg: str):
        line = f"{utc()} | {msg}"
        with self._lock:
            self.job["log"].append(line)
            self.job["log"] = self.job["log"][-500:]
        if self.case.get("folder"):
            with open(Path(self.case["folder"]) / "case_log.txt", "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def open_case(self, data: dict, log=True):
        folder = (data.get("folder") or "").strip()
        if not folder:
            raise ValueError("choose a case folder")
        d = Path(folder)
        d.mkdir(parents=True, exist_ok=True)
        cj = d / "case.json"
        case = json.loads(cj.read_text(encoding="utf-8")) if cj.exists() else {}
        for k in ("case_number", "examiner", "agency", "description"):
            if data.get(k) is not None and data.get(k) != "":
                case[k] = data[k]
        case["folder"] = str(d.resolve())
        case.setdefault("created", utc())
        cj.write_text(json.dumps(case, indent=2), encoding="utf-8")
        self.case = case
        self._save_settings()
        if log:
            self.case_log(f"Case opened: {case.get('case_number', '')} at {case['folder']} "
                          f"({APP_NAME} {__version__})")
        ev = d / "evidence.json"
        if ev.exists():
            e = json.loads(ev.read_text(encoding="utf-8"))
            self.source, self.evidence_hash = e.get("source", {}), e.get("hash", {})
        return case

    def _save_evidence(self):
        if self.case.get("folder"):
            (Path(self.case["folder"]) / "evidence.json").write_text(
                json.dumps({"source": self.source, "hash": self.evidence_hash}, indent=2), encoding="utf-8")

    def set_source(self, path: str):
        with open_source(path) as s:
            self.source = s.describe()
        self.evidence_hash = {}
        self._save_evidence()
        self.case_log(f"Evidence selected (read-only): {path} - {self.source['size']:,} bytes, "
                      f"type {self.source['kind']}")
        return self.source

    # ---------------------------------------------------------------- jobs
    def _start(self, kind: str, target):
        with self._lock:
            if self.job["running"]:
                raise RuntimeError(f"a {self.job['type']} job is already running")
            self._cancel.clear()
            self.job.update(type=kind, running=True, progress={}, result=None, error=None)

        def wrap():
            try:
                res = target()
                with self._lock:
                    self.job["result"] = res
            except Exception as e:  # noqa: BLE001
                with self._lock:
                    self.job["error"] = str(e)
                self.case_log(f"{kind} failed: {e}")
                traceback.print_exc()
            finally:
                with self._lock:
                    self.job["running"] = False
        threading.Thread(target=wrap, daemon=True).start()

    def start_hash(self):
        if not self.source:
            raise ValueError("select evidence first")
        path = self.source["path"]

        def run():
            self.case_log(f"Hashing evidence {path}")
            with open_source(path) as s:
                r = hash_source(s, progress=lambda d, t: self._prog(done=d, total=t),
                                cancel=self._cancel.is_set)
            r["when"] = utc()
            self.evidence_hash = r
            self._save_evidence()
            self.case_log(f"Evidence MD5 {r['md5']}  SHA-256 {r['sha256']}")
            return r
        self._start("hash", run)

    def _prog(self, **kw):
        with self._lock:
            self.job["progress"] = kw

    def start_carve(self, data: dict):
        if not self.case.get("folder"):
            raise ValueError("open or create a case first")
        if not self.source:
            raise ValueError("select evidence first")
        ids = data.get("signature_ids") or []
        sigs = [s for s in self.lib.all() if s["id"] in ids]
        bad = [f"{s['name']}: {'; '.join(s['problems'])}" for s in sigs if s.get("problems")]
        if bad:
            raise ValueError("fix these signatures first - " + " | ".join(bad))
        if not sigs:
            raise ValueError("select at least one signature")
        resume = (data.get("resume_run") or "").strip()
        runs = Path(self.case["folder"]) / "runs"
        if resume:
            out = runs / Path(resume).name
            if not out.exists():
                raise ValueError(f"run {resume} not found")
        else:
            out = runs / ("carve_" + _dt.datetime.now().strftime("%Y%m%d_%H%M%S"))
        size = int(self.source["size"])
        start = int(data.get("start") or 0)
        end = int(data.get("end") or 0) or size
        if not (0 <= start < end <= size):
            raise ValueError("range must satisfy 0 <= start < end <= evidence size")
        opt = CarveOptions(out_dir=str(out), start=start, end=end,
                           chunk_size=max(1, int(data.get("chunk_mb") or 64)) * 1024 * 1024,
                           dry_run=bool(data.get("dry_run")),
                           force_sector_aligned=bool(data.get("aligned")),
                           max_items=int(data.get("max_items") or 0), resume=bool(resume))
        path = self.source["path"]

        def run():
            with open_source(path) as s:
                c = Carver(s, sigs, opt,
                           progress=lambda st: self._prog(done=st.scanned, total=st.total,
                                                          items=st.items, elapsed=st.elapsed),
                           cancel=self._cancel.is_set, log=self.case_log)
                st = c.run()
            rep = build_report(out, self.case, self.evidence_hash)
            self.case_log(f"Report written: {rep}")
            return {"run": out.name, "items": st.items, "canceled": st.canceled}
        self._start("carve", run)
        return out.name

    def cancel(self):
        self._cancel.set()

    # ---------------------------------------------------------------- runs
    def runs(self):
        if not self.case.get("folder"):
            return []
        d = Path(self.case["folder"]) / "runs"
        out = []
        for r in sorted(d.glob("carve_*"), reverse=True) if d.exists() else []:
            sess = r / "carve_session.json"
            info = {"name": r.name, "complete": sess.exists()}
            if sess.exists():
                s = json.loads(sess.read_text(encoding="utf-8"))
                info.update(items=s["stats"]["items"], canceled=s["stats"]["canceled"],
                            finished=s["stats"]["finished"], dry_run=s["options"]["dry_run"])
            out.append(info)
        return out

    def run_items(self, name: str):
        import csv
        p = Path(self.case["folder"]) / "runs" / Path(name).name / "carve_log.csv"
        if not p.exists():
            return []
        with open(p, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    # ---------------------------------------------------------------- signatures
    def test_signature(self, sig: dict, path: str, limit: int = 50):
        errs = check(sig)
        if errs:
            raise SignatureError("; ".join(errs))
        with tempfile.TemporaryDirectory() as td, open_source(path) as s:
            c = Carver(s, [normalize(sig)], CarveOptions(out_dir=td, dry_run=True, max_items=limit))
            st = c.run()
            return {"items": [i.row() for i in c.items], "rejected": st.rejected,
                    "scanned": st.scanned}

    def state(self):
        with self._lock:
            job = json.loads(json.dumps(self.job))
        return {"app": APP_NAME, "version": __version__, "case": self.case,
                "source": self.source, "evidence_hash": self.evidence_hash, "job": job,
                "platform": sys.platform}


def browse(path: str):
    if not path:
        if sys.platform.startswith("win"):
            drives = [f"{c}:\\" for c in string.ascii_uppercase if os.path.exists(f"{c}:\\")]
            return {"path": "", "parent": "", "dirs": drives, "files": []}
        path = str(Path.home())
    p = Path(path)
    if p.is_file():
        p = p.parent
    dirs, files = [], []
    try:
        for e in sorted(p.iterdir(), key=lambda x: x.name.lower()):
            try:
                if e.is_dir():
                    dirs.append(e.name)
                elif e.is_file():
                    files.append({"name": e.name, "size": e.stat().st_size})
            except OSError:
                continue
    except OSError as e:
        return {"path": str(p), "parent": str(p.parent), "dirs": [], "files": [], "error": str(e)}
    parent = "" if p.parent == p else str(p.parent)
    return {"path": str(p), "parent": parent, "dirs": dirs, "files": files}


def open_in_os(path: Path):
    if sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        os.system(f'open "{path}"')
    else:
        os.system(f'xdg-open "{path}" >/dev/null 2>&1 &')


def make_handler(app: App, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class H(BaseHTTPRequestHandler):
        server_version = f"DFX/{__version__}"

        def log_message(self, fmt, *args):  # quiet console
            pass

        def _json(self, obj, code=200):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _host_ok(self):
            if self.headers.get("Host") not in allowed_hosts:
                self._json({"error": "bad host"}, 403)
                return False
            return True

        def _file(self, p: Path, ctype=None):
            if not p.is_file():
                return self._json({"error": "not found"}, 404)
            data = p.read_bytes()
            if p.name == "index.html":
                data = data.replace(b"__DFX_TOKEN__", app.token.encode())
            self.send_response(200)
            self.send_header("Content-Type", ctype or mimetypes.guess_type(str(p))[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if not self._host_ok():
                return
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            try:
                if u.path in ("/", "/index.html"):
                    return self._file(WEB / "index.html", "text/html; charset=utf-8")
                if u.path.startswith("/static/"):
                    name = Path(unquote(u.path[8:])).name
                    return self._file(WEB / name)
                if u.path.startswith("/runs/") and app.case.get("folder"):
                    parts = unquote(u.path[6:]).split("/")
                    if len(parts) == 2 and parts[1] == "report.html":
                        return self._file(Path(app.case["folder"]) / "runs" / Path(parts[0]).name / "report.html",
                                          "text/html; charset=utf-8")
                if u.path == "/api/state":
                    return self._json(app.state())
                if u.path == "/api/signatures":
                    return self._json(app.lib.all())
                if u.path == "/api/drives":
                    return self._json(list_physical_drives())
                if u.path == "/api/browse":
                    return self._json(browse(q.get("path", "")))
                if u.path == "/api/runs":
                    return self._json(app.runs())
                if u.path == "/api/run":
                    return self._json(app.run_items(q.get("name", "")))
                return self._json({"error": "not found"}, 404)
            except Exception as e:  # noqa: BLE001
                return self._json({"error": str(e)}, 400)

        def do_POST(self):
            if not self._host_ok():
                return
            if self.headers.get("X-DFX-Token") != app.token:
                return self._json({"error": "missing or bad token"}, 403)
            n = int(self.headers.get("Content-Length") or 0)
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
            except json.JSONDecodeError:
                return self._json({"error": "bad JSON"}, 400)
            p = urlparse(self.path).path
            try:
                if p == "/api/case":
                    return self._json(app.open_case(data))
                if p == "/api/source":
                    return self._json(app.set_source(data.get("path", "")))
                if p == "/api/hash":
                    app.start_hash()
                    return self._json({"ok": True})
                if p == "/api/carve":
                    return self._json({"run": app.start_carve(data)})
                if p == "/api/cancel":
                    app.cancel()
                    return self._json({"ok": True})
                if p == "/api/signatures":
                    s = app.lib.save_user(data)
                    app.case_log(f"Signature saved: {s['id']} ({s['name']})")
                    return self._json(s)
                if p == "/api/signatures/delete":
                    ok = app.lib.delete_user(data.get("id", ""))
                    if ok:
                        app.case_log(f"User signature deleted: {data.get('id')}")
                    return self._json({"ok": ok})
                if p == "/api/signatures/test":
                    return self._json(app.test_signature(data.get("signature", {}), data.get("path", ""),
                                                         int(data.get("limit") or 50)))
                if p == "/api/report":
                    run = Path(app.case["folder"]) / "runs" / Path(data.get("run", "")).name
                    return self._json({"report": str(build_report(run, app.case, app.evidence_hash))})
                if p == "/api/open":
                    base = Path(app.case["folder"])
                    run = data.get("run")
                    target = base / "runs" / Path(run).name if run else base
                    open_in_os(target)
                    return self._json({"ok": True})
                return self._json({"error": "not found"}, 404)
            except (ValueError, RuntimeError, SourceError, SignatureError, FileExistsError, OSError) as e:
                return self._json({"error": str(e)}, 400)

    return H


def serve(port: int = DEFAULT_PORT, open_browser: bool = True):
    app = App()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app, port))
    url = f"http://127.0.0.1:{port}/"
    print(f"{APP_NAME} {__version__} running at {url}  (Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
