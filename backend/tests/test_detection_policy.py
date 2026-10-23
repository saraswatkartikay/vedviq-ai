"""Regression tests for scam signals, cautious unknowns, URL safety and OCR limits."""
import io
import hashlib
import json

import pytest
from PIL import Image

from app import main
from app.schemas import MLAssessment, ThreatIntelResult
from app.services import analyzer
from app.services.language import detect_language
from ml.train import groups_for, grouped_split


def assessment(probability=None):
    return MLAssessment(
        status='untrained', predicted_label='unknown', calibrated_probability=probability,
        top_features=[], model_version=None, note='test assessment',
    )


@pytest.mark.parametrize('message', [
    'Share your OTP and enter UPI PIN to receive cashback',
    'Mujhe refund bhejne ke liye UPI request approve karo, PIN daalna',
    'बैंक खाता आज बंद हो जाएगा, तुरंत केवाईसी अपडेट करें',
    'CBI says you are under digital arrest, stay on WhatsApp video or arrest warrant will be issued',
    'Install AnyDesk now so bank support can process your refund',
    'You won a prize; pay a processing fee to claim the reward',
])
def test_high_risk_scam_patterns_are_not_low(message):
    indicators, _, _, ml = analyzer.analyze_text(message)
    value, level, *_ = analyzer.score(indicators, ml)
    assert indicators
    assert value == min(100, sum(item.weight for item in indicators))
    assert level in ('High', 'Critical')


@pytest.mark.parametrize('message', [
    'Never share your OTP or UPI PIN with anyone. Your bank will never ask for them.',
    'UPI PIN कभी भी पैसे प्राप्त करने के लिए दर्ज न करें।',
    'Never share your OTP. Please share OTP now.',
])
def test_safety_advice_does_not_suppress_or_create_false_positive(message):
    indicators, _, _, _ = analyzer.analyze_text(message)
    if message.endswith('Please share OTP now.'):
        assert any(item.id == 'OTP_CREDENTIAL_THEFT' for item in indicators)
    else:
        assert not any(item.id in ('OTP_CREDENTIAL_THEFT', 'UPI_PIN_REQUEST') for item in indicators)


def test_rule_evidence_survives_conflicting_low_model_estimate():
    indicators, _, _, _ = analyzer.analyze_text('Share your OTP and enter UPI PIN to receive cashback')
    value, level, summary, *_ = analyzer.score(indicators, assessment(.582))
    assert level == 'Critical'
    assert value == min(100, sum(item.weight for item in indicators))
    assert 'not a probability' in summary
    assert value == analyzer.score(indicators, assessment(.02))[0]


def test_uncalibrated_classifier_alone_cannot_change_score_or_category():
    baseline = analyzer.score([], assessment(None))
    value, level, summary, *_ = analyzer.score([], assessment(.582))
    assert value == baseline[0] == 0
    assert level == baseline[1] == 'Low'
    assert 'insufficient' in summary.lower()
    assert 'not a probability' in summary
    assert '18/100' not in summary


def test_external_malicious_match_is_distinguished_from_unknown_reputation():
    malicious = ThreatIntelResult(provider='test feed', mode='live_api', verdict='malicious', details='provider match')
    unknown = ThreatIntelResult(provider='test feed', mode='offline_fallback', verdict='unknown', details='not checked')
    value, level, summary, *_ = analyzer.score([], assessment(.99), malicious, scan_type='url')
    unknown_value, unknown_level, unknown_summary, *_ = analyzer.score([], assessment(.99), unknown, scan_type='url')
    assert (value, level) == (40, 'Critical')
    assert 'external threat feed match' in summary.lower()
    assert (unknown_value, unknown_level) == (0, 'Low')
    assert 'unknown or unavailable' in unknown_summary


# These concise strings are synthetic normalization regressions written for
# tests; they are not collected or labeled real-world SMS, and are not training data.
@pytest.mark.parametrize(('language_hint', 'message'), [
    ('en', 'Your bank account will be blocked today. Update KYC immediately.'),
    ('hi', 'आपका बैंक खाता बंद हो जाएगा, तुरंत केवाईसी अपडेट करें।'),
    ('hinglish', 'Aapka bank khata band ho jayega, turant KYC update karo.'),
    ('bn', 'আপনার ব্যাংক অ্যাকাউন্ট বন্ধ হবে, এখনই কেওয়াইসি আপডেট করুন।'),
    ('mr', 'तुमचे बँक खाते बंद होईल, त्वरित केवायसी अपडेट करा।'),
    ('te', 'మీ బ్యాంక్ ఖాతా నిలిపివేయబడుతుంది, వెంటనే KYC నవీకరించండి।'),
    ('ta', 'உங்கள் வங்கி கணக்கு முடக்கப்படும், உடனே KYC புதுப்பிக்கவும்।'),
    ('gu', 'તમારું બેંક ખાતું બંધ થશે, તરત KYC અપડેટ કરો।'),
    ('ur', 'آپ کا بینک اکاؤنٹ بند ہو جائے گا، فوراً KYC اپ ڈیٹ کریں۔'),
    ('kn', 'ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಮುಚ್ಚಲಾಗುತ್ತದೆ, ತಕ್ಷಣ KYC ನವೀಕರಿಸಿ।'),
    ('ml', 'നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് ബ്ലോക്ക് ചെയ്യും, ഉടൻ KYC പുതുക്കുക।'),
    ('or', 'ଆପଣଙ୍କ ବ୍ୟାଙ୍କ ଖାତା ବନ୍ଦ ହେବ, ତୁରନ୍ତ KYC ଅପଡେଟ କରନ୍ତୁ।'),
    ('pa', 'ਤੁਹਾਡਾ ਬੈਂਕ ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ, ਤੁਰੰਤ KYC ਅੱਪਡੇਟ ਕਰੋ।'),
    ('as', "আপোনাৰ বেংক একাউণ্ট বন্ধ হ'ব, এতিয়াই KYC আপডেট কৰক।"),
])
def test_synthetic_native_script_and_code_mix_scam_phrases(language_hint, message):
    indicators, _, _, ml = analyzer.analyze_text(message, language_hint)
    assert any(item.id == 'KYC_ACCOUNT_BLOCK' for item in indicators)
    assert ml.calibrated_probability is None
    assert ml.status == 'rules_only'
    assert ml.detected_language == language_hint
    assert analyzer.score(indicators, ml)[1] == 'High'


@pytest.mark.parametrize(('language_hint', 'message'), [
    ('en', 'Your bank payment was received successfully. Thank you.'),
    ('hi', 'धन्यवाद, आपका भुगतान सफल हुआ।'),
    ('hinglish', 'Dhanyavaad, aapka payment safal hua.'),
    ('bn', 'ধন্যবাদ, আপনার পেমেন্ট সফল হয়েছে।'),
    ('mr', 'धन्यवाद, तुमचे पेमेंट यशस्वी झाले।'),
    ('te', 'ధన్యవాదాలు, మీ చెల్లింపు విజయవంతమైంది।'),
    ('ta', 'நன்றி, உங்கள் கட்டணம் வெற்றிகரமாக முடிந்தது।'),
    ('gu', 'આભાર, તમારી ચુકવણી સફળ થઈ.'),
    ('ur', 'شکریہ، آپ کی ادائیگی کامیاب ہو گئی۔'),
    ('kn', 'ಧನ್ಯವಾದಗಳು, ನಿಮ್ಮ ಪಾವತಿ ಯಶಸ್ವಿಯಾಗಿದೆ.'),
    ('ml', 'നന്ദി, നിങ്ങളുടെ പേയ്‌മെന്റ് വിജയകരമായി പൂർത്തിയായി.'),
    ('or', 'ଧନ୍ୟବାଦ, ଆପଣଙ୍କ ଦେୟ ସଫଳ ହୋଇଛି।'),
    ('pa', 'ਧੰਨਵਾਦ, ਤੁਹਾਡਾ ਭੁਗਤਾਨ ਸਫਲ ਰਿਹਾ।'),
    ('as', 'ধন্যবাদ, আপোনাৰ পেমেণ্ট সফল হৈছে।'),
])
def test_synthetic_legitimate_lookalikes_are_not_high_risk(language_hint, message):
    indicators, _, _, ml = analyzer.analyze_text(message, language_hint)
    value, level, *_ = analyzer.score(indicators, ml)
    assert not any(item.severity in ('high', 'critical') for item in indicators)
    assert level not in ('High', 'Critical')


@pytest.mark.parametrize('url', [
    'http://127.0.0.1/admin', 'http://2130706433/admin', 'http://0x7f000001/',
    'http://0177.0.0.1/', 'http://localhost/', 'http://service.internal/',
])
def test_private_and_legacy_numeric_hosts_are_blocked(url):
    with pytest.raises(ValueError):
        analyzer.analyze_url(url)


def test_url_userinfo_is_detected_and_path_brand_is_not_misread():
    _, userinfo_indicators, _ = analyzer.analyze_url('https://trusted.com@evil.example/login')
    assert any(item.id == 'URL_USERINFO' for item in userinfo_indicators)
    _, path_indicators, _ = analyzer.analyze_url('https://example.com/path/sbi-login')
    assert not any(item.id == 'URL_BRAND_IMPERSONATION' for item in path_indicators)


@pytest.mark.parametrize('url', ['', 'http://', 'https://example.com:bad/path', 'javascript:alert(1)', 'http://example.com\\@127.0.0.1'])
def test_malformed_or_ambiguous_urls_are_rejected(url):
    with pytest.raises(ValueError):
        analyzer.analyze_url(url)


def test_brand_lookalike_is_high_risk():
    _, indicators, _ = analyzer.analyze_url('https://sbi-login.example.com')
    assert any(item.id == 'URL_BRAND_IMPERSONATION' for item in indicators)
    value, level, *_ = analyzer.score(indicators, assessment(), scan_type='url')
    assert value == sum(item.weight for item in indicators)
    assert level == 'Critical'


def test_safe_browsing_miss_and_timeout_remain_unknown(monkeypatch):
    monkeypatch.setattr(analyzer, 'SAFE_BROWSING_API_KEY', 'test-key')

    class Response:
        def raise_for_status(self): pass
        def json(self): return {}

    monkeypatch.setattr(analyzer.httpx, 'post', lambda *args, **kwargs: Response())
    assert analyzer.threat_result('https://example.com').verdict == 'unknown'

    def timeout(*args, **kwargs):
        raise TimeoutError('private detail should not be logged')

    monkeypatch.setattr(analyzer.httpx, 'post', timeout)
    result = analyzer.threat_result('https://example.com')
    assert result.verdict == 'unknown'
    assert 'TimeoutError' in result.details

    class MatchResponse(Response):
        def json(self): return {'matches': [{'threatType': 'SOCIAL_ENGINEERING'}]}

    monkeypatch.setattr(analyzer.httpx, 'post', lambda *args, **kwargs: MatchResponse())
    assert analyzer.threat_result('https://example.com').verdict == 'malicious'


def png_bytes(size=(16, 16)):
    image = Image.new('RGB', size, 'white')
    output = io.BytesIO()
    image.save(output, format='PNG')
    return output.getvalue()


def test_ocr_manual_text_uses_shared_analyzer(client):
    response = client.post('/api/v1/analyze/ocr', files={'file': ('shot.png', png_bytes(), 'image/png')}, data={'manual_text': 'Share your OTP to receive cashback'})
    assert response.status_code == 200
    assert response.json()['scan_type'] == 'ocr'
    assert response.json()['risk_level'] in ('High', 'Critical')


def test_ocr_rejects_malformed_image_even_with_manual_text(client):
    response = client.post('/api/v1/analyze/ocr', files={'file': ('shot.png', b'\x89PNG\r\n\x1a\nnot an image', 'image/png')}, data={'manual_text': 'Please review this screenshot text'})
    assert response.status_code == 400


def test_ocr_rejects_empty_upload(client):
    response = client.post('/api/v1/analyze/ocr', files={'file': ('empty.png', b'', 'image/png')}, data={'manual_text': 'some text'})
    assert response.status_code == 400


def test_ocr_limits_manual_text_and_image_dimensions(client):
    too_much_text = client.post('/api/v1/analyze/ocr', files={'file': ('shot.png', png_bytes(), 'image/png')}, data={'manual_text': 'x' * 10001})
    assert too_much_text.status_code == 413
    too_large_image = client.post('/api/v1/analyze/ocr', files={'file': ('shot.png', png_bytes((5000, 5000)), 'image/png')}, data={'manual_text': 'valid manual text'})
    assert too_large_image.status_code == 413


def test_empty_and_oversized_messages_are_rejected_by_schema(client):
    assert client.post('/api/v1/analyze/message', json={'text': ''}).status_code == 422
    assert client.post('/api/v1/analyze/message', json={'text': 'x' * 10001}).status_code == 422


def test_api_reports_language_and_classifier_limit(client):
    response = client.post('/api/v1/analyze/message', json={
        'text': 'আপনার ব্যাংক অ্যাকাউন্ট বন্ধ হবে, এখনই কেওয়াইসি আপডেট করুন।',
        'language_hint': 'bn',
    })
    assert response.status_code == 200
    result = response.json()
    assert result['ml_assessment']['detected_language'] == 'bn'
    assert result['ml_assessment']['status'] == 'rules_only'
    assert result['risk_level'] in ('High', 'Critical')


@pytest.mark.parametrize(('message', 'expected'), [
    ('Please update your profile when convenient.', 'en'),
    ('आपका बैंक खाता बंद होगा।', 'hi'),
    ('Aapka bank khata band ho jayega, turant KYC update karo.', 'hinglish'),
    ('আপনার ব্যাংক অ্যাকাউন্ট বন্ধ হবে, এখনই কেওয়াইসি আপডেট করুন।', 'bn'),
    ('তোমাৰ বেংক একাউণ্ট বন্ধ হ\'ব, এতিয়াই KYC আপডেট কৰক।', 'as'),
    ('तुमचे बँक खाते बंद होईल, त्वरित केवायसी अपडेट करा।', 'mr'),
    ('మీ బ్యాంక్ ఖాతా నిలిపివేయబడుతుంది, వెంటనే KYC నవీకరించండి।', 'te'),
    ('உங்கள் வங்கி கணக்கு முடக்கப்படும், உடனே KYC புதுப்பிக்கவும்।', 'ta'),
    ('તમારું બેંક ખાતું બંધ થશે, તરત KYC અપડેટ કરો।', 'gu'),
    ('آپ کا بینک اکاؤنٹ بند ہو جائے گا، فوراً KYC اپ ڈیٹ کریں۔', 'ur'),
    ('ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆ ಮುಚ್ಚಲಾಗುತ್ತದೆ, ತಕ್ಷಣ KYC ನವೀಕರಿಸಿ।', 'kn'),
    ('നിങ്ങളുടെ ബാങ്ക് അക്കൗണ്ട് ബ്ലോക്ക് ചെയ്യും, ഉടൻ KYC പുതുക്കുക।', 'ml'),
    ('ଆପଣଙ୍କ ବ୍ୟାଙ୍କ ଖାତା ବନ୍ଦ ହେବ, ତୁରନ୍ତ KYC ଅପଡେଟ କରନ୍ତୁ।', 'or'),
    ('ਤੁਹਾਡਾ ਬੈਂਕ ਖਾਤਾ ਬੰਦ ਹੋ ਜਾਵੇਗਾ, ਤੁਰੰਤ KYC ਅੱਪਡੇਟ ਕਰੋ।', 'pa'),
])
def test_best_effort_language_identification_is_not_risk(message, expected):
    detected, _, _ = detect_language(message)
    assert detected == expected


def test_unfamiliar_script_does_not_get_classifier_benign_label():
    _, _, _, ml = analyzer.analyze_text('Ваш банковский счет заблокирован, срочно подтвердите данные.')
    assert ml.status == 'rules_only'
    assert ml.predicted_label == 'unknown'
    assert ml.calibrated_probability is None


def test_training_groups_near_duplicates_and_rejects_conflicting_labels():
    groups = groups_for(
        ['Your account is blocked today, update KYC immediately', 'Your account is blocked today update KYC immediately', 'Normal lunch plans for today'],
        ['scam', 'scam', 'benign'],
    )
    assert groups[0] == groups[1]
    assert groups[2] != groups[0]
    with pytest.raises(SystemExit, match='Conflicting labels'):
        groups_for(['Your account is blocked today, update KYC immediately', 'Your account is blocked today update KYC immediately'], ['scam', 'benign'])


def test_training_splits_keep_duplicate_groups_together():
    texts = [f'scam example {i}' for i in range(12)] + [f'benign example {i}' for i in range(12)]
    labels = ['scam'] * 12 + ['benign'] * 12
    texts.extend(['A repeated scam template, update account now', 'A repeated scam template update account now'])
    labels.extend(['scam', 'scam'])
    groups = groups_for(texts, labels)
    split = grouped_split(texts, labels, groups)
    membership = {index: name for name, indexes in split.items() for index in indexes}
    assert membership[24] == membership[25]


def test_model_loader_uses_versioned_artifact_and_rejects_hash_mismatch(tmp_path, monkeypatch):
    import joblib
    artifact = tmp_path / 'model-v2.joblib'
    joblib.dump({'model': 'v2'}, artifact)
    metadata = {'artifact_file': artifact.name, 'artifact_sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()}
    (tmp_path / 'metadata.json').write_text(json.dumps(metadata), encoding='utf-8')
    monkeypatch.setattr(analyzer, 'ARTIFACT_DIR', tmp_path)
    assert analyzer._load_model() == {'model': 'v2'}
    artifact.write_bytes(b'changed')
    assert analyzer._load_model() is None
    (tmp_path / 'metadata.json').unlink()
    assert analyzer._load_model() is None


def test_system_status_reports_model_scope(client):
    response = client.get('/api/v1/system/status')
    assert response.status_code == 200
    metadata = response.json()['model_metadata']
    assert 'en' in metadata['rule_processing_languages']
    assert metadata['language_performance_validated'] is False
    assert metadata['status'] == 'trained_demo'
