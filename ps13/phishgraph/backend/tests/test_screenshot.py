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


# ---- one realistic OCR transcript per app layout ------------------------------------------------------------------
IPHONE_SMS = """9:41
LTE
< 12
AX-HDFCBK >
Text Message • SMS
Today 9:12 AM
Your HDFC Bank NetBanking is blocked. Reactivate
now at hdfc-netbanking-verify.in/login to avoid
charges.
The sender is not in your contact list. Report Junk"""

WHATSAPP = """Rahul Boss
online
Messages and calls are end-to-end encrypted. No one outside of this chat can read them.
Hi, I'm in a meeting. Need you to buy 4 Amazon 10:02 pm
gift cards of ₹5,000 each urgently 10:02 pm ✓✓
Send codes to +91 98765 43210 10:03 pm"""

GMAIL_APP = """Inbox
Action required: verify your Microsoft 365 account Inbox
M
Microsoft Security 10:24 AM
to me
Your mailbox storage is full. Verify at
https://microsoft-login-security.xyz/verify
Reply
Reply all
Forward"""

GMAIL_WEB = """Invoice INV-20931 overdue External Inbox
Accounts Team (billing@invoice-portal.top)
Sep 28, 2026, 10:24 AM (2 hours ago)
to me
Please pay the attached invoice today via
https://invoice-portal.top/pay"""

OUTLOOK = """From: DHL Express <noreply@dhl-parcel-track.info>
Sent: Monday, September 28, 2026 10:24 AM
To: Anirudh
Subject: Your parcel is on hold
Pay the Rs. 49 customs fee at
http://dhl-parcel-track.info/pay"""


def test_iphone_messages_layout():
    x = extract_from_ocr(IPHONE_SMS)
    assert (x.channel, x.sender) == ('sms', 'AX-HDFCBK')
    assert x.entities['urls'][0]['registrable'] == 'hdfc-netbanking-verify.in'
    assert 'Report Junk' not in x.body and 'LTE' not in x.body and x.body.startswith('Your HDFC Bank')


def test_whatsapp_layout_strips_bubble_times():
    x = extract_from_ocr(WHATSAPP)
    assert (x.channel, x.sender) == ('whatsapp', 'Rahul Boss')
    assert '10:02' not in x.body and '✓' not in x.body and 'encrypted' not in x.body
    assert x.entities['phones'] == ['+919876543210'] and '₹5,000' in x.entities['amounts']


def test_gmail_app_sender_from_to_me_anchor():
    x = extract_from_ocr(GMAIL_APP)
    assert x.channel == 'email'
    assert x.sender == 'Microsoft Security' and x.subject == 'Action required: verify your Microsoft 365 account'
    assert x.body.startswith('Your mailbox storage is full') and 'Reply' not in x.body


def test_gmail_web_parenthesised_address():
    x = extract_from_ocr(GMAIL_WEB)
    assert x.sender == 'Accounts Team <billing@invoice-portal.top>'
    assert x.subject == 'Invoice INV-20931 overdue'
    assert 'ago' not in x.body


def test_outlook_headers():
    x = extract_from_ocr(OUTLOOK)
    assert x.sender == 'DHL Express <noreply@dhl-parcel-track.info>' and x.subject == 'Your parcel is on hold'
    assert 'Sent:' not in x.body and 'To:' not in x.body and 'Rs. 49' in x.entities['amounts']


def test_lookalike_characters_are_never_corrected():
    x = extract_from_ocr('Sign in at https://g00gle.com/login now')
    assert x.entities['urls'][0]['registrable'] == 'g00gle.com'  # the digits are the attack, keep them
