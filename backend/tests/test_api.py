def test_health(client):
    assert client.get('/health').json()['status']=='ok'
def test_message_analysis_and_history(client):
    r=client.post('/api/v1/analyze/message',json={'text':'Share your OTP and enter UPI PIN to receive cashback'})
    assert r.status_code==200
    assert r.json()['risk_level'] in ('High','Critical')
    assert r.json()['scan_id']>0
    hist=client.get('/api/v1/history')
    assert hist.status_code==200 and isinstance(hist.json(),list)
def test_private_url_blocked(client):
    r=client.post('/api/v1/analyze/url',json={'url':'http://127.0.0.1:8000/admin'})
    assert r.status_code==400
def test_url_analysis(client):
    r=client.post('/api/v1/analyze/url',json={'url':'http://sbi-kyc-update.xyz/login'})
    assert r.status_code==200
    assert r.json()['risk_level'] in ('High','Critical')
def test_dashboard(client):
    assert client.get('/api/v1/dashboard').status_code==200
