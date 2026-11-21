"""
AEGIS // Zero-Touch PC-Compute & High-Security Workspace
Komplett selbststartend: installiert Pakete bei Bedarf, sucht freien Port,
erstellt lokales HTTPS-Zertifikat und öffnet automatisch den Browser.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys


def ensure_dependencies() -> None:
    """Installiert fehlende Python-Bibliotheken automatisch ohne Terminal-Befehle."""
    required = {
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "cryptography": "cryptography",
    }
    missing = [pkg for mod, pkg in required.items() if importlib.util.find_spec(mod) is None]
    if missing:
        print(f"[AEGIS] Installiere einmalig benötigte Pakete: {', '.join(missing)} ...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", *missing])


ensure_dependencies()

import asyncio
import base64
import datetime
import hashlib
import ipaddress
import secrets
import socket
import threading
import time
import webbrowser
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
import uvicorn

# ==============================================================================
# 1. EINSTELLUNGEN
# ==============================================================================

APP_NAME = "AEGIS"
APP_VERSION = "1.5.0-bulletproof"
HOST = "0.0.0.0"
PREFERRED_PORT = 8443
MAX_PORT_TRIES = 50

BASE_DIR = Path(__file__).resolve().parent
CERT_DIR = BASE_DIR / ".aegis_tls"
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"

SESSION_COOKIE_NAME = "aegis_device_session"
MAX_HISTORY_ITEMS = 200
RATE_LIMIT_WINDOW_SEC = 60
RATE_LIMIT_MAX_REQUESTS = 300


# ==============================================================================
# 2. AUTOMATISCHER PORT, LOKALE IP & HTTPS-ZERTIFIKAT
# ==============================================================================

def get_local_ip() -> str:
    """Findet automatisch die lokale IP des PCs im Heimnetz."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return str(sock.getsockname()[0])
    except Exception:
        return "127.0.0.1"


def find_free_port(host: str, start_port: int, tries: int = MAX_PORT_TRIES) -> int:
    """Sucht automatisch den ersten freien Port, damit es nie einen Port-Konflikt gibt."""
    for offset in range(tries):
        port = start_port + offset
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError("Kein freier Port gefunden.")


def ensure_tls_cert() -> tuple[str, str]:
    """Erstellt automatisch ein eigenes lokales TLS-Zertifikat für verschlüsseltes HTTPS."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    if CERT_FILE.exists() and KEY_FILE.exists():
        return str(CERT_FILE), str(KEY_FILE)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    local_ip = get_local_ip()
    hostname = socket.gethostname() or "localhost"

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AEGIS Local"),
            x509.NameAttribute(NameOID.COMMON_NAME, local_ip),
        ]
    )

    san_list: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.DNSName(hostname),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
    except ValueError:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(private_key, hashes.SHA256())
    )

    KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return str(CERT_FILE), str(KEY_FILE)


# ==============================================================================
# 3. PC-RECHENKERN & LIVE-SYNCHRONISATION (RAM-ONLY)
# ==============================================================================

class EphemeralRateLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._salt = secrets.token_hex(32)

    def _client_key(self, request: Request) -> str:
        host = request.client.host if request.client else "unknown"
        return hashlib.blake2b(f"{self._salt}:{host}".encode("utf-8"), digest_size=16).hexdigest()

    def allow(self, request: Request) -> bool:
        now = time.monotonic()
        key = self._client_key(request)
        bucket = self._buckets[key]
        while bucket and (now - bucket[0]) > self.window_seconds:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            return False
        bucket.append(now)
        return True


class PcComputeEngine:
    def __init__(self) -> None:
        self.instance_id = secrets.token_hex(8)
        self.master_key_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        self.quick_pair_token = secrets.token_urlsafe(24)
        self.active_sessions: set[str] = set()
        self.entries: deque[dict[str, Any]] = deque(maxlen=MAX_HISTORY_ITEMS)
        self.sockets: set[WebSocket] = set()
        self.lock = asyncio.Lock()

    def issue_session_token(self) -> str:
        token = secrets.token_urlsafe(32)
        self.active_sessions.add(token)
        return token

    def is_valid_session(self, token: str | None) -> bool:
        return bool(token and token in self.active_sessions)

    def rotate_pair_token(self) -> str:
        self.quick_pair_token = secrets.token_urlsafe(24)
        return self.quick_pair_token

    async def add_entry(self, source_device: str, text: str) -> dict[str, Any]:
        digest = hashlib.sha256(
            f"{time.time_ns()}:{source_device}:{text}".encode("utf-8")
        ).hexdigest()[:16]
        item = {
            "id": digest,
            "source": source_device,
            "text": text,
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        }
        async with self.lock:
            self.entries.append(item)
            targets = list(self.sockets)

        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_json({"type": "entry_added", "item": item})
            except Exception:
                dead.append(ws)

        if dead:
            async with self.lock:
                for ws in dead:
                    self.sockets.discard(ws)

        return item

    async def register_ws(self, ws: WebSocket) -> None:
        async with self.lock:
            self.sockets.add(ws)

    async def unregister_ws(self, ws: WebSocket) -> None:
        async with self.lock:
            self.sockets.discard(ws)


pc_engine = PcComputeEngine()
rate_limiter = EphemeralRateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SEC)

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


@app.middleware("http")
async def security_middleware(request: Request, call_next: Any) -> Any:
    if not rate_limiter.allow(request):
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Zu viele Anfragen. Bitte kurz warten."},
        )

    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'; "
        "form-action 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()"
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


# ==============================================================================
# 4. API & ZERO-TOUCH HANDY-ZUGANG
# ==============================================================================

class EntryCreateRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=16000)
    source: str = Field(default="PC-Kern", min_length=1, max_length=32)


@app.get("/pair")
async def instant_pair_handy(token: str) -> RedirectResponse:
    if not secrets.compare_digest(token, pc_engine.quick_pair_token):
        raise HTTPException(status_code=403, detail="Ungültiger oder abgelaufener Pairing-Token.")

    session_token = pc_engine.issue_session_token()
    pc_engine.rotate_pair_token()

    redirect = RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    redirect.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        max_age=60 * 60 * 24 * 365,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return redirect


@app.get("/api/v1/status")
async def get_system_status(request: Request, response: Response) -> dict[str, Any]:
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not pc_engine.is_valid_session(cookie_token):
        client_ip = request.client.host if request.client else ""
        if client_ip in ("127.0.0.1", "::1"):
            new_token = pc_engine.issue_session_token()
            response.set_cookie(
                key=SESSION_COOKIE_NAME,
                value=new_token,
                max_age=60 * 60 * 24 * 365,
                httponly=True,
                samesite="lax",
                path="/",
            )
        else:
            raise HTTPException(status_code=401, detail="Gerät nicht gekoppelt. Bitte /pair nutzen.")

    local_ip = get_local_ip()
    active_port = getattr(request.app.state, "active_port", PREFERRED_PORT)
    pair_url = f"https://{local_ip}:{active_port}/pair?token={pc_engine.quick_pair_token}"
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "pc_compute_active": True,
        "instance_id": pc_engine.instance_id,
        "local_ip": local_ip,
        "active_port": active_port,
        "pair_url": pair_url,
        "entries": list(pc_engine.entries),
    }


@app.post("/api/v1/entries")
async def create_entry(payload: EntryCreateRequest, request: Request) -> dict[str, Any]:
    if not pc_engine.is_valid_session(request.cookies.get(SESSION_COOKIE_NAME)):
        raise HTTPException(status_code=401, detail="Nicht autorisiert.")
    item = await pc_engine.add_entry(payload.source, payload.text)
    return {"item": item}


@app.websocket("/ws/v1/live")
async def live_stream(websocket: WebSocket) -> None:
    session_token = websocket.cookies.get(SESSION_COOKIE_NAME)
    client_host = websocket.client.host if websocket.client else ""
    if not pc_engine.is_valid_session(session_token) and client_host not in ("127.0.0.1", "::1"):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    await pc_engine.register_ws(websocket)
    try:
        await websocket.send_json({"type": "snapshot", "entries": list(pc_engine.entries)})
        while True:
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await pc_engine.unregister_ws(websocket)
    except Exception:
        await pc_engine.unregister_ws(websocket)


# ==============================================================================
# 5. STARTSEITE (SCHRITT 1)
# ==============================================================================

STARTPAGE_HTML = r"""<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AEGIS // Sicherer PC-Kern &amp; Startseite</title>
  <style>
    :root {
      --bg-base: #06080c;
      --bg-card: #0d121a;
      --bg-elevated: #141c28;
      --border: #202c3d;
      --border-accent: #38bdf8;
      --text-main: #f1f5f9;
      --text-dim: #94a3b8;
      --text-mute: #64748b;
      --accent: #0ea5e9;
      --accent-hover: #0284c7;
      --ok: #10b981;
      --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background:
        radial-gradient(circle at 12% 12%, rgba(14, 165, 233, 0.10), transparent 38%),
        radial-gradient(circle at 88% 85%, rgba(16, 185, 129, 0.08), transparent 42%),
        var(--bg-base);
      color: var(--text-main);
      font-family: var(--sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      border-bottom: 1px solid var(--border);
      background: rgba(13, 18, 26, 0.85);
      backdrop-filter: blur(12px);
      padding: 1rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
      flex-wrap: wrap;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.7rem;
      font-weight: 700;
      letter-spacing: 0.1em;
      font-size: 1.05rem;
    }
    .pulse-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--ok);
      box-shadow: 0 0 12px var(--ok);
    }
    .nav-group { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .nav-btn {
      padding: 0.45rem 0.9rem;
      border-radius: 7px;
      font-size: 0.84rem;
      font-weight: 600;
      border: 1px solid var(--border);
      background: var(--bg-elevated);
      color: var(--text-dim);
      cursor: pointer;
    }
    .nav-btn.active {
      border-color: var(--border-accent);
      color: var(--text-main);
      background: rgba(14, 165, 233, 0.16);
    }
    .nav-btn.locked { opacity: 0.45; cursor: not-allowed; }
    main {
      max-width: 1100px;
      width: 100%;
      margin: 2.25rem auto;
      padding: 0 1.5rem;
      flex: 1;
    }
    .grid {
      display: grid;
      grid-template-columns: 1.2fr 0.8fr;
      gap: 1.75rem;
      align-items: start;
    }
    @media (max-width: 880px) {
      .grid { grid-template-columns: 1fr; }
      header { padding: 1rem; }
    }
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.75rem;
      box-shadow: 0 18px 40px rgba(0, 0, 0, 0.45);
    }
    .kicker {
      font-family: var(--mono);
      font-size: 0.75rem;
      color: var(--ok);
      letter-spacing: 0.1em;
      text-transform: uppercase;
      margin-bottom: 0.55rem;
    }
    h1 { font-size: 1.8rem; line-height: 1.2; margin-bottom: 0.75rem; }
    .lead { color: var(--text-dim); font-size: 0.95rem; margin-bottom: 1.5rem; }
    .status-strip {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 0.75rem;
      margin-bottom: 1.5rem;
    }
    @media (max-width: 600px) { .status-strip { grid-template-columns: 1fr; } }
    .metric {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.8rem 0.95rem;
    }
    .metric-label { font-size: 0.74rem; color: var(--text-mute); margin-bottom: 0.25rem; }
    .metric-val { font-family: var(--mono); font-size: 0.86rem; color: var(--text-main); font-weight: 600; }
    .metric-val.ok { color: var(--ok); }
    label { display: block; font-size: 0.82rem; font-weight: 600; color: var(--text-dim); margin-bottom: 0.45rem; }
    input[type="text"], textarea {
      width: 100%;
      background: var(--bg-base);
      border: 1px solid var(--border);
      border-radius: 9px;
      padding: 0.75rem 0.95rem;
      color: var(--text-main);
      font-family: var(--mono);
      font-size: 0.86rem;
      outline: none;
    }
    input:focus, textarea:focus { border-color: var(--border-accent); }
    .btn-row { display: flex; gap: 0.75rem; flex-wrap: wrap; margin-top: 0.85rem; }
    button {
      padding: 0.72rem 1.15rem;
      border-radius: 8px;
      border: none;
      font-weight: 600;
      font-size: 0.88rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: var(--accent-hover); }
    .btn-ghost { background: var(--bg-elevated); color: var(--text-main); border: 1px solid var(--border); }
    .btn-ghost:hover { border-color: var(--text-dim); }
    .feed { margin-top: 1.5rem; border-top: 1px solid var(--border); padding-top: 1.25rem; }
    .feed-list {
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
      max-height: 260px;
      overflow-y: auto;
      margin-top: 0.75rem;
    }
    .feed-item {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0.7rem 0.9rem;
      font-size: 0.88rem;
    }
    .feed-meta {
      display: flex;
      justify-content: space-between;
      font-family: var(--mono);
      font-size: 0.74rem;
      color: var(--text-mute);
      margin-bottom: 0.25rem;
    }
    .side-stack { display: flex; flex-direction: column; gap: 1rem; }
    .info-box {
      background: var(--bg-elevated);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 0.95rem 1.05rem;
    }
    .info-title { font-size: 0.88rem; font-weight: 700; margin-bottom: 0.3rem; color: var(--text-main); }
    .info-desc { font-size: 0.82rem; color: var(--text-dim); }
    .notice {
      margin-top: 1rem;
      padding: 0.7rem 0.95rem;
      border-radius: 8px;
      font-size: 0.83rem;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.35);
      color: #a7f3d0;
    }
    .hidden { display: none !important; }
    footer {
      border-top: 1px solid var(--border);
      padding: 1rem 2rem;
      text-align: center;
      font-family: var(--mono);
      font-size: 0.75rem;
      color: var(--text-mute);
    }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span class="pulse-dot"></span>
      <span>AEGIS // PC-COMPUTE KERN</span>
    </div>
    <nav class="nav-group">
      <button class="nav-btn active">01. Startseite</button>
      <button class="nav-btn locked" title="Folgt in Schritt 2">02. Schreibraum (Bald)</button>
      <button class="nav-btn locked" title="Folgt in Schritt 3">03. Sicherer Kanal (Bald)</button>
    </nav>
  </header>

  <main>
    <div class="grid">
      <section class="card">
        <div class="kicker">SCHRITT 01 // STARTSEITE &amp; DAUERHAFTER PC-RECHENKERN</div>
        <h1>Schreiben ohne Reibung – Rechenlast auf dem PC</h1>
        <p class="lead">
          Dein PC läuft im Hintergrund und übernimmt die Verarbeitung. Auf dem Handy öffnest du einfach die App und bist sofort startklar – ohne jedes Mal neu einrichten zu müssen.
        </p>

        <div class="status-strip">
          <div class="metric">
            <div class="metric-label">PC-Rechenkern</div>
            <div class="metric-val ok" id="pcState">AKTIV</div>
          </div>
          <div class="metric">
            <div class="metric-label">Live-Verbindung</div>
            <div class="metric-val" id="wsState">VERBINDE...</div>
          </div>
          <div class="metric">
            <div class="metric-label">Aktiver Port</div>
            <div class="metric-val" id="portState">...</div>
          </div>
        </div>

        <label for="quickText">Schneller Live-Test (PC verarbeitet &amp; synchronisiert sofort)</label>
        <input type="text" id="quickText" placeholder="Text eingeben und Enter drücken..." maxlength="2000" />
        <div class="btn-row">
          <button class="btn-primary" id="btnSendQuick">An PC-Kern senden</button>
          <button class="btn-ghost" id="btnCopyHandyLink">Einmal-Handy-Link kopieren</button>
        </div>

        <div id="noticeBox" class="notice hidden"></div>

        <div class="feed">
          <label>Live-Puffer auf dem PC (synchron mit Handy &amp; PC)</label>
          <div class="feed-list" id="feedList"></div>
        </div>
      </section>

      <aside class="side-stack">
        <div class="card">
          <div class="kicker">ZERO-TOUCH HANDY-START</div>
          <p class="info-desc" style="margin-bottom: 0.75rem;">
            Kopiere den Einmal-Link unten, öffne ihn einmal auf deinem Handy und bestätige ggf. das lokale HTTPS-Zertifikat – danach klappt jedes erneute Öffnen direkt:
          </p>
          <textarea id="pairUrlBox" rows="3" readonly></textarea>
        </div>

        <div class="info-box">
          <div class="info-title">1. Rechenarbeit auf dem PC</div>
          <div class="info-desc">
            Der PC verarbeitet Eingaben zentral, hält den Live-Stream offen und ist später bereit für lokale KI-Module.
          </div>
        </div>

        <div class="info-box">
          <div class="info-title">2. Kein Setup auf dem Handy</div>
          <div class="info-desc">
            Nach dem einmaligen Öffnen des Pairing-Links bleibt die Sitzung aktiv – App öffnen und direkt loslegen.
          </div>
        </div>

        <div class="info-box">
          <div class="info-title">3. Gehärtete Verbindung</div>
          <div class="info-desc">
            Lokales TLS (HTTPS/WSS), automatischer freier Port, strikte Security-Header und kein unkontrolliertes Logging.
          </div>
        </div>
      </aside>
    </div>
  </main>

  <footer>
    AEGIS PC-COMPUTE // MODULARES BASIS-SYSTEM SCHRITT 1
  </footer>

  <script>
    (() => {
      "use strict";

      const quickInput = document.getElementById("quickText");
      const btnSend = document.getElementById("btnSendQuick");
      const btnCopyLink = document.getElementById("btnCopyHandyLink");
      const pairUrlBox = document.getElementById("pairUrlBox");
      const feedList = document.getElementById("feedList");
      const wsState = document.getElementById("wsState");
      const portState = document.getElementById("portState");
      const noticeBox = document.getElementById("noticeBox");

      const deviceLabel = /Android|iPhone|iPad|Mobile/i.test(navigator.userAgent)
        ? "Handy"
        : "PC-Browser";

      function showNotice(msg) {
        noticeBox.textContent = msg;
        noticeBox.classList.remove("hidden");
      }

      function escapeHtml(str) {
        return str
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;");
      }

      function renderEntry(item) {
        if (document.querySelector('[data-entry-id="' + item.id + '"]')) return;
        const div = document.createElement("div");
        div.className = "feed-item";
        div.setAttribute("data-entry-id", item.id);
        div.innerHTML =
          '<div class="feed-meta">' +
          "<span>" + escapeHtml(item.source) + "</span>" +
          "<span>" + escapeHtml(item.timestamp) + "</span>" +
          "</div>" +
          "<div>" + escapeHtml(item.text) + "</div>";
        feedList.prepend(div);
      }

      async function loadInitialStatus() {
        const res = await fetch("/api/v1/status", { credentials: "same-origin" });
        if (!res.ok) {
          showNotice("Bitte einmal den Einmal-Pairing-Link vom PC öffnen.");
          return;
        }
        const data = await res.json();
        if (data.active_port) {
          portState.textContent = String(data.active_port);
        }
        if (data.pair_url) {
          pairUrlBox.value = data.pair_url;
        }
        feedList.innerHTML = "";
        (data.entries || []).forEach(renderEntry);
      }

      async function sendEntry() {
        const text = quickInput.value.trim();
        if (!text) return;
        quickInput.value = "";
        const res = await fetch("/api/v1/entries", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({ text: text, source: deviceLabel })
        });
        if (res.ok) {
          const data = await res.json();
          if (data.item) renderEntry(data.item);
        }
      }

      function connectWebSocket() {
        const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
        const ws = new WebSocket(proto + "//" + window.location.host + "/ws/v1/live");

        ws.onopen = () => {
          wsState.textContent = "LIVE";
          wsState.classList.add("ok");
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === "snapshot" && Array.isArray(msg.entries)) {
              feedList.innerHTML = "";
              msg.entries.forEach(renderEntry);
            } else if (msg.type === "entry_added" && msg.item) {
              renderEntry(msg.item);
            }
          } catch (_) {}
        };

        ws.onclose = () => {
          wsState.textContent = "NEU VERBINDEN...";
          wsState.classList.remove("ok");
          setTimeout(connectWebSocket, 1500);
        };
      }

      btnSend.addEventListener("click", sendEntry);
      quickInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") sendEntry();
      });

      btnCopyLink.addEventListener("click", async () => {
        if (!pairUrlBox.value) return;
        try {
          await navigator.clipboard.writeText(pairUrlBox.value);
          showNotice("Einmal-Handy-Link kopiert. Auf dem Handy öffnen – danach läuft alles automatisch.");
        } catch (_) {
          pairUrlBox.select();
          showNotice("Link markiert – bitte kopieren und auf dem Handy öffnen.");
        }
      });

      loadInitialStatus().then(connectWebSocket);
    })();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def home_page(request: Request) -> HTMLResponse:
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    client_ip = request.client.host if request.client else ""
    html_response = HTMLResponse(content=STARTPAGE_HTML)

    if not pc_engine.is_valid_session(cookie_token) and client_ip in ("127.0.0.1", "::1"):
        token = pc_engine.issue_session_token()
        html_response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=token,
            max_age=60 * 60 * 24 * 365,
            httponly=True,
            samesite="lax",
            path="/",
        )
    return html_response


def open_browser_soon(url: str, delay: float = 1.2) -> None:
    def _runner() -> None:
        time.sleep(delay)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=_runner, daemon=True).start()


if __name__ == "__main__":
    cert_path, key_path = ensure_tls_cert()
    ip = get_local_ip()
    active_port = find_free_port(HOST, PREFERRED_PORT, MAX_PORT_TRIES)
    app.state.active_port = active_port

    pc_url = f"https://127.0.0.1:{active_port}"
    handy_url = f"https://{ip}:{active_port}/pair?token={pc_engine.quick_pair_token}"

    print(f"[{APP_NAME}] PC-Rechenkern startet auf Port {active_port}")
    print(f"  - PC Browser: {pc_url}")
    print(f"  - Handy Link: {handy_url}")

    open_browser_soon(pc_url)

    uvicorn.run(
        app,
        host=HOST,
        port=active_port,
        ssl_certfile=cert_path,
        ssl_keyfile=key_path,
        log_level="warning",
        access_log=False,
    )