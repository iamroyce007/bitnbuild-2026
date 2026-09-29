"""The brand-claim guarantee (services/brand_guard.py), checked exhaustively for EVERY protected brand:
a message presenting itself as brand B with a link outside B's official domains is never ALLOWed; genuine messages
from B's own domain linking to B's own site are not touched by the rule."""
import asyncio

import pytest

from app.services.brand_engine import get_brand_engine
from app.services.email_parser import parse_json_message
from app.services.pipeline import analyze

BRANDS = get_brand_engine().brands


def run(**kw):
    return asyncio.run(analyze(parse_json_message(**kw), source='test', persist=False))


def display(b):
    """How an impersonator writes the brand: its first name of 3+ letters ("X / Twitter" -> "Twitter")."""
    names = [n.strip() for n in b.name.split('/')] + list(b.keywords)
    return next(n for n in names if len(n) >= 3)


@pytest.mark.parametrize('b', BRANDS, ids=lambda b: b.name)
def test_every_brand_name_is_recognised_as_a_claim(b):
    assert any(c.name == b.name for c in get_brand_engine().claimed_brands(f'{display(b)} Security Team'))


@pytest.mark.parametrize('b', BRANDS, ids=lambda b: b.name)
def test_impersonation_with_unofficial_link_is_never_allowed(b):
    label = b.domains[0].split('.')[0]
    for link in (f'https://{label}-account-review.xyz/verify', 'https://sites.google.com/view/account-review-center'):
        r = run(subject=f'{display(b)}: important notice about your account', sender=f'{display(b)} Support <notice@mailer-{label}.help>',
                body=f'Please review your account details here: {link}', channel='email')
        assert r['decision'] != 'ALLOW', (b.name, link, r['risk_score'])
        from app.services.brand_guard import family
        assert any(family(get_brand_engine().official_brand(b.domains[0]) or b) == family(b) or g['brand'] == b.name for g in r['brand_guard'])


@pytest.mark.parametrize('b', BRANDS, ids=lambda b: b.name)
def test_sms_impersonation_is_never_allowed(b):
    label = b.domains[0].split('.')[0]
    r = run(sender='+919812345678', body=f'{display(b)}: your account needs KYC update today. Verify your details at {label}-kyc-verify.site/login',
            channel='sms')
    assert r['decision'] != 'ALLOW', (b.name, r['risk_score'])


@pytest.mark.parametrize('b', BRANDS, ids=lambda b: b.name)
def test_genuine_brand_mail_is_not_touched(b):
    d = b.domains[0]
    r = run(subject=f'{display(b)}: your monthly statement is ready', sender=f'{display(b)} <noreply@{d}>',
            body=f'Your statement is available when you sign in at https://{d}/', channel='email')
    assert 'brand_guard' not in r, (b.name, r.get('brand_guard'))


def test_registered_bank_header_transaction_alert_is_allowed():
    # a genuine debit alert from a TRAI-registered header; the payee handle swiggy@icici is not an identity claim
    r = run(sender='AX-HDFCBK', channel='sms',
            body='Rs 2,500.00 debited from a/c **1234 on 28-09-26 to VPA swiggy@icici. Not you? Call 18002586161.')
    assert r['decision'] == 'ALLOW', (r['risk_score'], r['reasons'][:2])


def test_header_of_one_bank_claiming_another_gets_no_trust():
    from app.services import metadata_engine
    from app.services.email_parser import parse_json_message as pj
    m = metadata_engine.analyze(pj(sender='AX-HDFCBK', channel='sms', body='SBI: your YONO account is blocked. Update KYC now.'))
    assert not m.trust
