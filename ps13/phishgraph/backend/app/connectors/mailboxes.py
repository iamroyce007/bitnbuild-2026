"""Live mailbox connectors (explicit opt-in: ENABLE_LIVE_EMAIL=true plus credentials).

  IMAP             IDLE-style polling of INBOX; new messages are analysed as they arrive
  Gmail API        OAuth refresh token -> users.messages list/get(format=raw)
  Microsoft Graph  client-credentials -> /users/{mailbox}/messages + /$value (MIME)
Quarantine actions (RESPONSE_LIVE_ACTIONS=true) only label/move messages; nothing is ever deleted.
"""
from __future__ import annotations

import asyncio
import base64
import imaplib
import logging

import httpx

from ..config import get_settings

log = logging.getLogger(__name__)
QUARANTINE_FOLDER = 'PhishGraph-Quarantine'


# ---------------- ingestion ----------------
async def poll_imap(seen: set[str]) -> list[tuple[str, bytes]]:
    s = get_settings()

    def _poll() -> list[tuple[str, bytes]]:
        out = []
        m = imaplib.IMAP4_SSL(s.imap_host)
        m.login(s.imap_user, s.imap_password)
        m.select('INBOX', readonly=True)
        _, data = m.uid('search', None, 'UNSEEN')
        for uid in (data[0].split() if data and data[0] else [])[-50:]:
            u = uid.decode()
            if u in seen:
                continue
            _, msg = m.uid('fetch', uid, '(BODY.PEEK[])')
            if msg and msg[0]:
                out.append((u, msg[0][1]))
        m.logout()
        return out
    return await asyncio.to_thread(_poll)


async def _gmail_token() -> str:
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post('https://oauth2.googleapis.com/token', data={'client_id': s.google_client_id, 'client_secret': s.google_client_secret,
                                                                      'refresh_token': s.google_refresh_token, 'grant_type': 'refresh_token'})
        r.raise_for_status()
        return r.json()['access_token']


async def poll_gmail(seen: set[str]) -> list[tuple[str, bytes]]:
    tok = await _gmail_token()
    out = []
    async with httpx.AsyncClient(timeout=20, headers={'Authorization': f'Bearer {tok}'}) as c:
        r = await c.get('https://gmail.googleapis.com/gmail/v1/users/me/messages', params={'q': 'in:inbox newer_than:1d', 'maxResults': 25})
        r.raise_for_status()
        for m in r.json().get('messages', []):
            if m['id'] in seen:
                continue
            raw = (await c.get(f'https://gmail.googleapis.com/gmail/v1/users/me/messages/{m["id"]}', params={'format': 'raw'})).json().get('raw', '')
            out.append((m['id'], base64.urlsafe_b64decode(raw + '===')))
    return out


async def _graph_token() -> str:
    s = get_settings()
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(f'https://login.microsoftonline.com/{s.microsoft_tenant_id}/oauth2/v2.0/token',
                         data={'client_id': s.microsoft_client_id, 'client_secret': s.microsoft_client_secret, 'scope': 'https://graph.microsoft.com/.default',
                               'grant_type': 'client_credentials'})
        r.raise_for_status()
        return r.json()['access_token']


async def poll_msgraph(seen: set[str]) -> list[tuple[str, bytes]]:
    s = get_settings()
    tok = await _graph_token()
    out = []
    base = f'https://graph.microsoft.com/v1.0/users/{s.microsoft_mailbox}'
    async with httpx.AsyncClient(timeout=20, headers={'Authorization': f'Bearer {tok}'}) as c:
        r = await c.get(f'{base}/mailFolders/inbox/messages', params={'$top': 25, '$select': 'id', '$orderby': 'receivedDateTime desc'})
        r.raise_for_status()
        for m in r.json().get('value', []):
            if m['id'] in seen:
                continue
            mime = await c.get(f'{base}/messages/{m["id"]}/$value')
            out.append((m['id'], mime.content))
    return out


def configured_sources() -> list[str]:
    s = get_settings()
    if not s.enable_live_email:
        return []
    out = []
    if s.imap_host and s.imap_user and s.imap_password:
        out.append('imap')
    if s.google_client_id and s.google_refresh_token:
        out.append('gmail')
    if s.microsoft_client_id and s.microsoft_tenant_id and s.microsoft_mailbox:
        out.append('msgraph')
    return out


async def mailbox_loop(interval: int = 30) -> None:
    """Continuously analyse new mail from every configured mailbox as it arrives."""
    from ..services.email_parser import parse_raw_email
    from ..services.pipeline import analyze
    pollers = {'imap': poll_imap, 'gmail': poll_gmail, 'msgraph': poll_msgraph}
    seen: dict[str, set[str]] = {k: set() for k in pollers}
    while True:
        for src in configured_sources():
            try:
                for mid, raw in await pollers[src](seen[src]):
                    seen[src].add(mid)
                    pm = parse_raw_email(raw)
                    pm.message_id = pm.message_id or mid
                    await analyze(pm, source=src)
            except Exception as e:
                log.warning('%s polling failed: %s', src, e)
        await asyncio.sleep(interval)


# ---------------- live response ----------------
def quarantine_live(source: str, message_id: str) -> tuple[str, str]:
    """Move/label a message. Called only when RESPONSE_LIVE_ACTIONS=true."""
    s = get_settings()
    if source == 'imap':
        m = imaplib.IMAP4_SSL(s.imap_host)
        m.login(s.imap_user, s.imap_password)
        m.create(QUARANTINE_FOLDER)
        m.select('INBOX')
        _, data = m.search(None, f'HEADER Message-ID "{message_id}"')
        for num in (data[0].split() if data and data[0] else []):
            m.copy(num, QUARANTINE_FOLDER)
            m.store(num, '+FLAGS', '\\Flagged')
        m.logout()
        return 'imap', f'copied to {QUARANTINE_FOLDER} and flagged (original kept)'
    return source, f'live {source} quarantine requires the message API id; recorded as simulated'
