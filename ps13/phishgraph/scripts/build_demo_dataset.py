"""Generate data/demo/demo_dataset.json: the seeded DEMO DATA (clearly labelled, fictional infrastructure).

IPs come from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and ASNs from the
RFC 5398 documentation range (AS64496-AS64511), so no demo indicator can be confused with a real one.
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

infra = {
    # --- Campaign A: Microsoft 365 credential harvesting (the centrepiece) ---
    'office365-auth-verify.top': {'ip': '203.0.113.45', 'asn': 'AS64500', 'asn_name': 'Demo BulletProof Hosting Ltd', 'ns': ['ns1.shadydns-demo.net', 'ns2.shadydns-demo.net'],
                                  'cert': 'demo-cert-a1f3', 'age_days': 9, 'registrar': 'Demo Registrar Inc'},
    'outlook-mailbox-restore.xyz': {'ip': '203.0.113.45', 'asn': 'AS64500', 'asn_name': 'Demo BulletProof Hosting Ltd', 'ns': ['ns1.shadydns-demo.net', 'ns2.shadydns-demo.net'],
                                    'cert': 'demo-cert-a1f3', 'age_days': 7, 'registrar': 'Demo Registrar Inc'},
    'ms-account-security.online': {'ip': '203.0.113.46', 'asn': 'AS64500', 'asn_name': 'Demo BulletProof Hosting Ltd', 'ns': ['ns1.shadydns-demo.net'],
                                   'cert': 'demo-cert-a1f3', 'age_days': 5, 'registrar': 'Demo Registrar Inc'},
    'sharepoint-docs-review.site': {'ip': '203.0.113.46', 'asn': 'AS64500', 'asn_name': 'Demo BulletProof Hosting Ltd', 'ns': ['ns2.shadydns-demo.net'],
                                    'cert': 'demo-cert-b7c2', 'age_days': 4, 'registrar': 'Demo Registrar Inc'},
    # the "never seen before" domain used in the live demo: no feed lists it, but it shares IP, NS and certificate
    'microsoft-login-security.example.xyz': {'ip': '203.0.113.45', 'asn': 'AS64500', 'asn_name': 'Demo BulletProof Hosting Ltd',
                                             'ns': ['ns1.shadydns-demo.net', 'ns2.shadydns-demo.net'], 'cert': 'demo-cert-a1f3', 'age_days': 2, 'registrar': 'Demo Registrar Inc'},
    'm365-password-expiry.help': {'ip': '203.0.113.47', 'asn': 'AS64500', 'asn_name': 'Demo BulletProof Hosting Ltd', 'ns': ['ns1.shadydns-demo.net'],
                                  'cert': 'demo-cert-b7c2', 'age_days': 1, 'registrar': 'Demo Registrar Inc'},
    # --- Campaign B: SBI / UPI KYC smishing ---
    'sbi-kyc-update.online': {'ip': '198.51.100.23', 'asn': 'AS64501', 'asn_name': 'Demo Cheap VPS Co', 'ns': ['ns1.freedns-demo.org'], 'cert': 'demo-cert-c9d0', 'age_days': 6, 'registrar': 'Demo Registrar Inc'},
    'yono-sbi-reward.top': {'ip': '198.51.100.23', 'asn': 'AS64501', 'asn_name': 'Demo Cheap VPS Co', 'ns': ['ns1.freedns-demo.org'], 'cert': 'demo-cert-c9d0', 'age_days': 3, 'registrar': 'Demo Registrar Inc'},
    'sbi-netbanking-kyc.site': {'ip': '198.51.100.24', 'asn': 'AS64501', 'asn_name': 'Demo Cheap VPS Co', 'ns': ['ns1.freedns-demo.org'], 'cert': 'demo-cert-c9d0', 'age_days': 2, 'registrar': 'Demo Registrar Inc'},
    # --- Campaign C: TNEB electricity disconnection scam ---
    'tneb-bill-pay.in': {'ip': '192.0.2.77', 'asn': 'AS64502', 'asn_name': 'Demo Offshore Hosting', 'ns': ['ns1.parkingdns-demo.com'], 'cert': 'demo-cert-e4a8', 'age_days': 11, 'registrar': 'Demo Registrar Inc'},
    'tnpdcl-update.online': {'ip': '192.0.2.77', 'asn': 'AS64502', 'asn_name': 'Demo Offshore Hosting', 'ns': ['ns1.parkingdns-demo.com'], 'cert': 'demo-cert-e4a8', 'age_days': 8, 'registrar': 'Demo Registrar Inc'},
    # --- Campaign D: parcel / customs fee ---
    'dhl-parcel-customs.top': {'ip': '192.0.2.88', 'asn': 'AS64503', 'asn_name': 'Demo Fast Hosting', 'ns': ['ns1.quickdns-demo.net'], 'cert': 'demo-cert-f1b2', 'age_days': 5, 'registrar': 'Demo Registrar Inc'},
    'indiapost-redelivery.xyz': {'ip': '192.0.2.88', 'asn': 'AS64503', 'asn_name': 'Demo Fast Hosting', 'ns': ['ns1.quickdns-demo.net'], 'cert': 'demo-cert-f1b2', 'age_days': 4, 'registrar': 'Demo Registrar Inc'},
}
feed = [  # "known bad" indicators already present in a (demo) threat feed before the demo starts
    'https://office365-auth-verify.top/common/oauth2/authorize', 'https://outlook-mailbox-restore.xyz/owa/restore', 'https://ms-account-security.online/login',
    'https://yono-sbi-reward.top/claim', 'https://tnpdcl-update.online/pay', 'https://dhl-parcel-customs.top/track',
]

benign = [
    {'subject': 'Your GitHub password was reset', 'sender': 'GitHub <noreply@github.com>', 'body': 'The password for your GitHub account was recently changed. If you did this, no further action is needed. If not, visit https://github.com/settings/security immediately.'},
    {'subject': 'Your Amazon.in order #404-8812211 has shipped', 'sender': 'Amazon.in <shipment-tracking@amazon.in>', 'body': 'Hello, your package is on the way and will arrive Thursday. Track your package: https://www.amazon.in/gp/your-account/order-history'},
    {'subject': 'Monthly statement for account ending 4421', 'sender': 'HDFC Bank <alerts@hdfcbank.com>', 'body': 'Dear Customer, your account statement for September is now available in NetBanking at https://netbanking.hdfcbank.com. HDFC Bank never asks for your OTP or PIN.'},
    {'subject': 'Invitation: Sprint review @ Thu 3pm', 'sender': 'Karthik <karthik@annauniv.edu>', 'body': 'Hi team, sending the invite for the sprint review. Agenda doc: https://docs.google.com/document/d/1AbCdEf/edit . See you there.'},
    {'subject': 'The Hindu - Morning Digest', 'sender': 'The Hindu <newsletter@thehindu.com>', 'body': 'Top stories today: monsoon update for Chennai, RBI policy review, and more. Read at https://www.thehindu.com/news/ . Unsubscribe any time.'},
    {'subject': 'Lab submission deadline extended', 'sender': 'Prof. Meena <meena@iitm.ac.in>', 'body': 'Dear students, the networks lab submission deadline is extended to Monday. Upload on the course page https://courses.iitm.ac.in as usual.'},
    {'subject': 'Your Swiggy order is on the way', 'sender': 'Swiggy <noreply@swiggy.in>', 'body': 'Your order from Saravana Bhavan is out for delivery. Track live in the app or at https://www.swiggy.com/my-account.'},
    {'subject': 'Zoom meeting notes', 'sender': 'Anil <anil@example.org>', 'body': 'Notes from today are attached in the shared drive. Recording link: https://zoom.us/rec/share/abc123 . Thanks for joining.'},
    {'subject': 'Microsoft 365 security info was updated', 'sender': 'Microsoft account team <account-security-noreply@accountprotection.microsoft.com>', 'body': 'The security info for your Microsoft account was updated. If this was you, you can safely ignore this. Review at https://account.microsoft.com/security'},
    {'subject': 'IRCTC booking confirmation PNR 4521887654', 'sender': 'IRCTC <ticketadmin@irctc.co.in>', 'body': 'Your e-ticket from MAS to SBC on 12-Oct is confirmed. View bookings at https://www.irctc.co.in/nget/booking-history'},
    {'channel': 'sms', 'sender': 'VM-SBIINB', 'body': 'Rs.2,500.00 debited from A/c XX4421 on 27-09 via UPI to SWIGGY. Not you? Call 1800 1234 (toll free). -SBI'},
    {'subject': 'Hackathon team registration confirmed', 'sender': 'Bit N Build <team@bitnbuild.example.org>', 'body': 'Your team registration for Bit N Build 2026 is confirmed. Problem statements are on the portal. Good luck!'},
]

phishing = [
    {'subject': 'Action required: your Microsoft 365 mailbox will be disabled', 'sender': 'Microsoft 365 Admin <admin@outlook-mailbox-restore.xyz>',
     'body': 'Dear user, your mailbox storage is full and your account will be suspended within 24 hours. Restore access immediately: https://outlook-mailbox-restore.xyz/owa/restore'},
    {'subject': 'Shared document: Q3 salary revision.pdf', 'sender': 'SharePoint Online <no-reply@sharepoint-docs-review.site>',
     'html': '<p>A document has been shared with you.</p><a href="https://sharepoint-docs-review.site/view?doc=q3">https://sharepoint.com/sites/HR/Q3.pdf</a><span style="display:none">newsletter weather sports cricket score</span>'},
    {'subject': 'Password expires today', 'sender': 'IT Helpdesk <helpdesk@m365-password-expiry.help>',
     'body': 'Your Office 365 password expires today. Keep your current password by signing in here: hxxps://m365-password-expiry[.]help/keep-password'},
    {'subject': 'Unusual sign-in activity', 'sender': 'Microsoft Account <security@ms-account-security.online>',
     'body': 'We detected unusual sign-in activity on your account. Please verify your identity: https://ms-account-security.online/login to avoid suspension.'},
    {'channel': 'sms', 'sender': '+917845123690', 'body': 'Dear SBI customer, your YONO account will be blocked today due to pending KYC. Update PAN now: sbi-netbanking-kyc.site/kyc . Share OTP with our officer to complete.'},
    {'channel': 'sms', 'sender': '+918122334455', 'body': 'Congratulations! You have won 7,500 SBI reward points. Redeem before midnight: https://yono-sbi-reward.top/claim'},
    {'channel': 'whatsapp', 'sender': '+919003112233', 'body': 'அன்புள்ள நுகர்வோரே, உங்கள் மின் இணைப்பு இன்று இரவு 9.30 மணிக்கு துண்டிக்கப்படும். கடந்த மாத பில் புதுப்பிக்கப்படவில்லை. உடனடியாக அழைக்கவும் 9876501234 அல்லது tneb-bill-pay.in'},
    {'channel': 'sms', 'sender': '+917200998877', 'body': 'Dear consumer your electricity power will be disconnected tonight at 9.30pm because previous month bill was not updated. Please immediately contact our electricity officer 9876501234 or pay at tnpdcl-update.online/pay'},
    {'subject': 'Your parcel is on hold at customs', 'sender': 'DHL Express <support@dhl-parcel-customs.top>', 'body': 'Your shipment could not be delivered. Pay the customs fee of Rs 49 to release your parcel: https://dhl-parcel-customs.top/track?id=IN4521'},
    {'channel': 'sms', 'sender': 'IndiaPost', 'body': 'India Post: your package is held at the warehouse due to incomplete address. Update within 12 hours: https://indiapost-redelivery.xyz/update'},
    {'subject': 'Quick favour', 'sender': 'Dr. Rajesh Kumar (Principal) <principal.office.desk@gmail.com>',
     'body': 'Are you available? I am in a meeting and need a quick favour. I need 5 Amazon gift cards of Rs 2000 each for a client, urgently. Keep this confidential, I will reimburse you today.'},
    {'subject': 'Cyber Crime Cell notice - case registered against your Aadhaar', 'sender': 'Cyber Crime Police <notice@cybercrime-gov-in.support>',
     'body': 'A money laundering case has been registered against your Aadhaar number. You must join a video call statement with the CBI officer today or an arrest warrant will be issued. Do not tell anyone about this investigation.'},
    {'subject': 'Invoice INV-20931 overdue', 'sender': 'Accounts <billing@vendor-payments-desk.xyz>', 'body': 'Please find the overdue invoice attached. Note our bank details have changed; process payment today to avoid penalty.',
     'attachments': ['INV-20931.pdf.html']},
    {'subject': 'Verify your PayPal account', 'sender': 'PayPal <service@paypa1-billing.com>', 'body': 'Your PayPal account has been limited. Confirm your details at https://paypa1-billing.com/webscr?cmd=login within 48 hours.'},
    {'subject': 'Google Drive: document shared with you', 'sender': 'Google Drive <drive-shares@gооgle-docs.com>',
     'body': 'Anjali shared "Salary_2026.xlsx" with you. Open: https://xn--ggle-docs-02ha.com/file/d/salary'},
]

out = {'label': 'DEMO DATA', 'note': 'Fictional infrastructure (RFC 5737 IPs, RFC 5398 ASNs). Never mixed with real threat intelligence.',
       'infrastructure': infra, 'feed': feed, 'benign': benign, 'phishing': phishing,
       'live_demo_email': {'subject': 'Your Microsoft account will be suspended', 'sender': 'Microsoft Security <security@microsoft-support-alert.xyz>',
                           'body': 'Dear user, we detected an unusual sign-in to your Microsoft account from a new device. Your account will be suspended within 24 hours. '
                                   'Verify your identity immediately at https://microsoft-login-security.example.xyz/verify to keep access.'},
       'live_demo_variant': {'subject': 'Microsoft 365: confirm your credentials', 'sender': 'Office 365 <noreply@o365-verify-portal.xyz>',
                             'body': 'Your employee account requires immediate validation. Sign in to continue using your mailbox: https://o365-verify-portal.xyz/signin'}}
out['infrastructure']['o365-verify-portal.xyz'] = {'ip': '203.0.113.45', 'asn': 'AS64500', 'asn_name': 'Demo BulletProof Hosting Ltd', 'ns': ['ns1.shadydns-demo.net'],
                                                   'cert': 'demo-cert-a1f3', 'age_days': 1, 'registrar': 'Demo Registrar Inc'}
(ROOT / 'data' / 'demo').mkdir(parents=True, exist_ok=True)
(ROOT / 'data' / 'demo' / 'demo_dataset.json').write_text(json.dumps(out, indent=1, ensure_ascii=False))
print(f'{len(benign)} benign, {len(phishing)} phishing, {len(infra)} demo domains, {len(feed)} demo feed IOCs')
