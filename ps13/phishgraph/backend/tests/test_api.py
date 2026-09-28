"""API integration: auth, analysis endpoints, detection retrieval, feedback loop, SSRF refusal, ops endpoints."""


def test_auth_required(client):
    assert client.post('/api/v1/analyze/url', json={'url': 'x.com'}).status_code == 401
    assert client.post('/api/v1/analyze/url', json={'url': 'x.com'}, headers={'X-API-Key': 'wrong'}).status_code == 401


def test_health_ready_metrics(client):
    assert client.get('/health').json()['status'] == 'ok'
    assert client.get('/ready').json()['ready'] is True
    assert 'phishgraph_requests_total' in client.get('/metrics').text


def test_analyze_url_google_vs_g00gle(client, auth):
    good = client.post('/api/v1/analyze/url', json={'url': 'https://www.google.com/'}, headers=auth).json()
    bad = client.post('/api/v1/analyze/url', json={'url': 'https://g00gle.com/login'}, headers=auth).json()
    assert good['decision'] == 'ALLOW' and good['risk_score'] < 10
    assert bad['decision'] in ('QUARANTINE', 'BLOCK') and bad['risk_score'] >= 70
    assert any('g00gle' in r['text'] for r in bad['reasons'])


def test_analyze_email_full_flow_and_feedback(client, auth):
    body = {'subject': 'Your Microsoft account will be suspended', 'sender': 'Microsoft Security <security@microsoft-support-alert.xyz>',
            'body': 'Unusual sign-in detected. Your account will be suspended within 24 hours. Verify your identity at https://microsoft-login-security.example.xyz/verify'}
    r = client.post('/api/v1/analyze/email', json=body, headers=auth)
    assert r.status_code == 200
    d = r.json()
    assert d['decision'] in ('QUARANTINE', 'BLOCK') and d['reasons'] and d['latency_ms'] < 5000
    assert d['report']['threat_intel']['sources']  # every provider reports a status
    det = client.get(f'/api/v1/detection/{d["detection_id"]}', headers=auth).json()
    assert det['report']['risk_score'] == d['risk_score'] and det['actions'][0]['mode'] == 'simulated'
    fb = client.post('/api/v1/feedback', json={'detection_id': d['detection_id'], 'label': 'confirmed_phishing'}, headers=auth).json()
    assert fb['iocs_added'] >= 1
    # the confirmed URL is now a known-bad IOC: re-analysis hits the local feed
    again = client.post('/api/v1/analyze/url', json={'url': 'https://microsoft-login-security.example.xyz/verify'}, headers=auth).json()
    assert any(s['source'] == 'local_intel' and s['verdict'] == 'malicious' for s in again['report']['threat_intel']['sources'])
    assert again['decision'] == 'BLOCK'


def test_benign_email_allowed(client, auth):
    body = {'subject': 'Team lunch', 'sender': 'Priya <priya@annauniv.edu>', 'body': 'Lunch is at 1pm Friday. Slides: https://docs.google.com/presentation/d/abc'}
    assert client.post('/api/v1/analyze/email', json=body, headers=auth).json()['decision'] == 'ALLOW'


def test_investigate_refuses_internal_targets(client, auth):
    for u in ('http://169.254.169.254/latest/meta-data', 'http://localhost:8000/', 'http://10.0.0.1/admin'):
        r = client.post('/api/v1/investigate', json={'url': u}, headers=auth)
        assert r.status_code == 400 and 'SSRF' in r.json()['detail']


def test_investigate_is_async(client, auth):
    r = client.post('/api/v1/investigate', json={'url': 'https://example-unknown-domain-for-test.xyz/login'}, headers=auth)
    assert r.status_code == 202 and r.json()['job_id']


def test_lists_and_statistics(client, auth):
    assert isinstance(client.get('/api/v1/detections', headers=auth).json(), list)
    st = client.get('/api/v1/statistics', headers=auth).json()
    assert st['total_detections'] >= 1 and 'graph' in st
    assert client.get('/api/v1/providers', headers=auth).json()['providers']
    assert 'registry' in client.get('/api/v1/models', headers=auth).json()


def test_validation_limits(client, auth):
    assert client.post('/api/v1/analyze/url', json={'url': 'a' * 5000}, headers=auth).status_code == 422
