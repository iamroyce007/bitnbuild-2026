"""Automated response. SAFE by default: actions only change PhishGraph's own database state (SIMULATED).
Live mailbox actions (label / move to quarantine) run only when RESPONSE_LIVE_ACTIONS=true AND the mailbox
connector is configured. Nothing is ever deleted."""
from __future__ import annotations

import logging

from ..config import get_settings
from ..database import session_scope
from ..models.database_models import AuditLog, Detection, ResponseAction

log = logging.getLogger(__name__)

PLAYBOOK = {
    'ALLOW': 'Delivered normally.',
    'FLAG': 'Delivered with a warning banner and added to the SOC review queue.',
    'QUARANTINE': 'Held in quarantine pending analyst review.',
    'BLOCK': 'Blocked; indicators added to the local threat feed and the graph.',
}


def respond(detection_id: str, decision: str, pm, source: str) -> dict:
    s = get_settings()
    live = s.response_live_actions and source in ('imap', 'gmail', 'msgraph')
    result = PLAYBOOK[decision]
    target = 'database'
    if live and decision in ('QUARANTINE', 'BLOCK'):
        try:
            from ..connectors.mailboxes import quarantine_live
            target, result = quarantine_live(source, pm.message_id)
        except Exception as e:  # never let a mailbox API failure break detection
            result = f'live action failed ({type(e).__name__}); simulated only'
            live = False
    if decision == 'BLOCK':
        from .intel_store import get_intel_store
        with session_scope() as ses:
            d = ses.get(Detection, detection_id)
            urls = [u['url'] for u in (d.report or {}).get('urls', []) if not u.get('trusted')] if d else []
        if urls:
            get_intel_store().add([('url', u) for u in urls], source='phishgraph_block', tags=['auto-block'], demo=False)
    with session_scope() as ses:
        ses.add(ResponseAction(detection_id=detection_id, action=decision, mode='live' if live else 'simulated', target=target, result=result))
        ses.add(AuditLog(actor='response_engine', action=f'response.{decision.lower()}', target=detection_id, detail={'mode': 'live' if live else 'simulated', 'result': result}))
    return {'action': decision, 'mode': 'live' if live else 'simulated', 'target': target, 'result': result}
