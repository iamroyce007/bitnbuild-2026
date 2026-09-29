"""Screenshot OCR text -> structured message + entities (OCR itself runs in the browser)."""
from app.services.screenshot_extractor import extract_from_ocr

SMS = """10:24 AM
87%
VM-SBIINB
Text Message
Today 9:12 AM
Dear SBI customer, your YONO account
will be blocked today due to pending
KYC. Update PAN within 24 hours at
https://sbi-kyc-upd
ate.site/kyc . Pay Rs. 10 fee via
sbikyc@ybl. Do not share OTP 482913
Delivered"""

GMAIL = """Inbox
Your PayPal account has been limited
PayPal Service <service@paypa1-billing.com>
to me
Dear customer,
Please confirm your details at
https;//paypa1-billing . com/webscr?cmd=login
within 48 hours.
Reply"""


def test_sms_screenshot_entities():
    x = extract_from_ocr(SMS)
    assert x.channel == 'sms' and x.sender == 'VM-SBIINB'
    assert x.entities['sender_header'] == {'header': 'VM-SBIINB', 'route': 'VM', 'entity': 'SBIINB'}
    assert [u['url'] for u in x.entities['urls']] == ['https://sbi-kyc-update.site/kyc']  # wrapped link rejoined
    assert x.entities['upi_ids'] == ['sbikyc@ybl'] and x.entities['codes'] == ['482913']
    assert 'within 24 hours' in x.entities['deadlines'] and 'State Bank of India' in x.entities['brands_claimed']
    assert '10:24 AM' in x.removed_lines and 'Delivered' in x.removed_lines and 'Delivered' not in x.body
    assert 'pending KYC' in x.body  # visual line breaks reflowed


def test_gmail_screenshot_layout_and_link_repair():
    x = extract_from_ocr(GMAIL)
    assert x.channel == 'email'
    assert x.subject == 'Your PayPal account has been limited'
    assert x.sender == 'PayPal Service <service@paypa1-billing.com>'
    assert x.entities['urls'][0]['registrable'] == 'paypa1-billing.com'
    assert any('http(s)' in r for r in x.repairs)
    assert 'to me' not in x.body and 'Reply' not in x.body


def test_no_invented_links_or_senders():
    x = extract_from_ocr('Visit www.example.com. Thanks\nBye')
    assert x.sender == '' and 'Visit' in x.body
    x = extract_from_ocr('Meet at 5. Pay . Now')
    assert x.entities['urls'] == [] and x.repairs == []
    assert extract_from_ocr('', ocr_confidence=40).warnings


def test_extract_endpoint(client, auth):
    r = client.post('/api/v1/extract', json={'text': GMAIL, 'hint': 'auto', 'ocr_confidence': 91}, headers=auth)
    assert r.status_code == 200 and r.json()['channel'] == 'email'


def test_reviewed_fields_are_kept_exactly():
    x = extract_from_ocr('', fields={'channel': 'email', 'sender': 'a@b.com', 'subject': 'Hi', 'body': 'go to evil-login.xyz/a now'})
    assert (x.sender, x.subject) == ('a@b.com', 'Hi') and x.entities['urls'][0]['registrable'] == 'evil-login.xyz'
