"""GAQ Telegram runner (public, read-only).

Runs on GitHub Actions every ~5 minutes. It:
  1. decrypts the latest status snapshot that the operator's PC publishes to this repo's `status` branch
     (AES-256-GCM; the public only ever sees ciphertext),
  2. answers read-only commands from the ONE authorised chat (the chat id travels inside the encrypted snapshot),
  3. relays alerts the PC could not deliver itself, and warns once if the PC stops publishing.

It has no command that can trade, resume, change risk or clear an emergency stop, and it has no path back to the PC:
nothing a Telegram user sends can reach the trading machine. Logs print counts only, never message content.

Secrets (GitHub Actions): TELEGRAM_BOT_TOKEN, RELAY_KEY (base64, 32 bytes).
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

STATUS = Path("status/status.enc")
STATE = Path(".relay_state/state.json")
STALE_MIN = 30
READ_ONLY_REPLY = ("This bot is READ-ONLY. It cannot trade, resume, change risk settings or clear the emergency stop. "
                   "Live control exists only on the operator's PC.")
HELP = ("GAQ read-only bot\n/status  live latch, EA, account snapshot\n/report  latest session report\n"
        "/research  latest research summary\n/news  latest important news\n/alerts  recent alerts\n/help  this list")
BLOCKED = {"/resume", "/trade", "/buy", "/sell", "/start_live", "/live", "/clear", "/reset", "/close", "/stop", "/risk", "/lot"}


RELAY_MAX_AGE_H = 6                                                     # never replay old history (e.g. after a cache reset)


def _age_h(iso: str) -> float:
    from datetime import datetime, timezone
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(iso)).total_seconds() / 3600
    except ValueError:
        return 1e9


def decrypt(blob: dict, key_b64: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = base64.b64decode(key_b64)
    pt = AESGCM(key).decrypt(base64.b64decode(blob["nonce"]), base64.b64decode(blob["ct"]), b"gaq-status-v1")
    return json.loads(pt.decode("utf-8"))


def api(token: str, method: str, **params):
    data = urllib.parse.urlencode(params).encode()
    with urllib.request.urlopen(f"https://api.telegram.org/bot{token}/{method}", data=data, timeout=30) as r:
        return json.load(r)


def send(token: str, chat_id: str, text: str) -> bool:
    try:
        return bool(api(token, "sendMessage", chat_id=chat_id, text=text[:4000], disable_web_page_preview="true").get("ok"))
    except Exception:                                                  # noqa: BLE001
        return False


def reply_for(cmd: str, snap: dict, age_min: float) -> str:
    stale = f"\n\n(!) PC snapshot is {age_min:.0f} min old - the PC or its publisher may be down." if age_min > STALE_MIN else ""
    c = cmd.split()[0].split("@")[0].lower() if cmd.strip() else ""
    if c in BLOCKED:
        return READ_ONLY_REPLY
    if c in ("/status", ""):
        return snap.get("status_text", "no status") + stale
    if c == "/report":
        return snap.get("session_report", "no session report yet") + stale
    if c == "/research":
        return snap.get("research_summary", "no research summary") + stale
    if c == "/news":
        return snap.get("news_text", "no news") + stale
    if c == "/alerts":
        al = snap.get("alerts", [])[-10:]
        return ("\n".join(f"{a['time_utc'][:16]} {a['level']}: {a['text']}" for a in al) or "no alerts") + stale
    return HELP


def main() -> int:
    token, key = os.environ.get("TELEGRAM_BOT_TOKEN", ""), os.environ.get("RELAY_KEY", "")
    if not token or not key:
        print("secrets missing - nothing to do")
        return 0
    if not STATUS.exists():
        print("no status snapshot published yet")
        return 0
    try:
        snap = decrypt(json.loads(STATUS.read_text()), key)
    except Exception as e:                                             # noqa: BLE001
        print(f"cannot decrypt snapshot ({type(e).__name__})")
        return 1
    chat = str(snap.get("chat_id") or "")
    age = (time.time() - float(snap.get("generated_unix", 0))) / 60
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    relayed = set(state.get("relayed", []))
    n_cmd = n_ign = n_rel = 0
    upd = api(token, "getUpdates", timeout=0).get("result", [])
    for u in upd:
        m = u.get("message") or {}
        if str(m.get("chat", {}).get("id")) != chat or not chat:
            n_ign += 1                                                 # only the authorised chat is answered
            continue
        send(token, chat, reply_for(m.get("text", ""), snap, age))
        n_cmd += 1
    if upd:
        api(token, "getUpdates", offset=upd[-1]["update_id"] + 1, timeout=0)   # acknowledge
    if chat:
        for a in snap.get("alerts", []):
            if not a.get("delivered_direct") and a["id"] not in relayed and _age_h(a.get("time_utc", "")) <= RELAY_MAX_AGE_H:
                if send(token, chat, f"GAQ {a['level']} (relayed): {a['text']}"):
                    relayed.add(a["id"])
                    n_rel += 1
        if age > STALE_MIN and not state.get("stale_warned"):
            if send(token, chat, f"GAQ WARNING: the PC has not published a status snapshot for {age:.0f} minutes. "
                                 "The PC, internet or publisher task may be down. (This bot cannot act; it only reports.)"):
                state["stale_warned"] = True
        elif age <= STALE_MIN:
            state["stale_warned"] = False
    state["relayed"] = sorted(relayed)[-500:]
    STATE.parent.mkdir(exist_ok=True)
    STATE.write_text(json.dumps(state))
    print(f"ok: commands {n_cmd}, ignored {n_ign}, relayed {n_rel}, snapshot age {age:.0f} min")
    return 0


if __name__ == "__main__":
    sys.exit(main())
