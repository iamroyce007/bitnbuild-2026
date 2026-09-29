"""URL parsing, Unicode/homograph analysis and the brand / look-alike engine (the "google vs g00gle" guarantees)."""
import pytest

from app.services.brand_engine import get_brand_engine
from app.utils.unicode_utils import is_mixed_script, skeleton, to_unicode
from app.utils.url_utils import parse_url, split_host, ssrf_block_reason, unwrap

E = get_brand_engine()


@pytest.mark.parametrize('host,reg', [
    ('mail.google.com', 'google.com'), ('www.sbi.co.in', 'sbi.co.in'), ('a.b.c.example.co.uk', 'example.co.uk'),
    ('foo.github.io', 'foo.github.io'), ('onlinesbi.sbi', 'onlinesbi.sbi'), ('x.y.web.app', 'y.web.app'),
])
def test_registrable_domain_uses_public_suffix_list(host, reg):
    assert split_host(host)[1] == reg


def test_parse_url_normalises_and_keeps_parts():
    p = parse_url('HTTP://User@WWW.Example.COM:8080/a/b?x=1#frag')
    assert p.host == 'www.example.com' and p.registrable == 'example.com' and p.port == 8080
    assert p.userinfo == 'User' and p.query == 'x=1' and p.fragment == 'frag'


def test_safelinks_unwrapped_statically():
    u = 'https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil-login.xyz%2Fverify&data=abc'
    assert 'https://evil-login.xyz/verify' in unwrap(u)


def test_skeleton_collapses_visual_confusables():
    assert skeleton('g00gle') == skeleton('google')
    assert skeleton('gооgle') == skeleton('google')  # Cyrillic o
    assert skeleton('rnicrosoft') == skeleton('microsoft')
    assert skeleton('google') != skeleton('goggle')


def test_mixed_script_and_punycode():
    assert is_mixed_script('pаypal')  # Cyrillic a
    assert not is_mixed_script('paypal')
    assert to_unicode('xn--ggle-55da.com') == 'gооgle.com'


@pytest.mark.parametrize('host', [
    'google.com', 'www.google.com', 'mail.google.com', 'accounts.google.com', 'google.co.in', 'googleapis.com', 'opensource.google',
    'paypal.com', 'www.paypal.com', 'microsoft.com', 'login.microsoftonline.com', 'onlinesbi.sbi', 'sbi.co.in', 'hdfcbank.com',
    'tnebltd.gov.in', 'wikipedia.org', 'github.com', 'bing.com', 'king.com', 'example.com', 'apple.com', 'amazon.in',
])
def test_legitimate_domains_are_never_flagged(host):
    v = E.analyze(host)
    assert v.findings == [], f'{host} wrongly flagged: {v.findings}'


@pytest.mark.parametrize('host,kind,brand', [
    ('g00gle.com', 'substitution', 'Google'),
    ('goog1e.com', 'substitution', 'Google'),
    ('gооgle.com', 'homograph', 'Google'),
    ('xn--ggle-55da.com', 'homograph', 'Google'),
    ('googel.com', 'typosquat', 'Google'),
    ('google.com.verify-login.xyz', 'subdomain_spoof', 'Google'),
    ('google-security-alert.com', 'combosquat', 'Google'),
    ('paypa1.com', 'substitution', 'PayPal'),
    ('rnicrosoft.com', 'substitution', 'Microsoft'),
    ('m1crosoft-support.net', 'combosquat', 'Microsoft'),
    ('sbi-kyc-update.online', 'combosquat', 'State Bank of India'),
    ('hdfcbnak.com', 'typosquat', 'HDFC Bank'),
    ('tneb-bill-pay.in', 'combosquat', 'TNEB / TNPDCL'),
    ('аpple.com', 'homograph', 'Apple'),
    ('netflix.xyz', 'tld_swap', 'Netflix'),
])
def test_lookalikes_are_caught_with_the_right_target(host, kind, brand):
    v = E.analyze(host)
    assert v.findings, f'{host} missed'
    f = v.findings[0]
    assert f.kind == kind and f.brand == brand, (host, f)
    assert f.evidence  # every finding explains itself


def test_everyday_words_are_not_brand_claims():
    assert E.analyze('appleseed-farm.org').findings == []
    assert E.claimed_brands('apple pie recipe') == []
    assert [b.name for b in E.claimed_brands('Your Apple ID is locked')] == ['Apple']
    assert [b.name for b in E.claimed_brands('Rs 500 debited -SBI')] == ['State Bank of India']


@pytest.mark.parametrize('host', ['localhost', '127.0.0.1', '169.254.169.254', '10.0.0.5', '192.168.1.1', '[::1]', 'metadata.google.internal',
                                  '0x7f000001', '2130706433', 'intranet.corp', 'printer.local'])
def test_ssrf_guard_blocks_internal_targets(host):
    assert ssrf_block_reason(host.strip('[]')) is not None


def test_ssrf_guard_allows_public_hosts():
    assert ssrf_block_reason('example.com') is None and ssrf_block_reason('8.8.8.8') is None


def test_permutation_squat_gitbuh():
    # reported miss: letters of "github" shuffled two apart (2 edits, so the typo index did not see it)
    from app.services.brand_engine import get_brand_engine
    be = get_brand_engine()
    for h in ('hyeonseok067.gitbuh.io', 'gitbuh.io'):
        f = be.analyze(h).findings
        assert f and f[0].kind == 'permutation' and f[0].brand == 'GitHub', h
    assert not be.analyze('hyeonseok067.github.io').findings      # genuine GitHub Pages site
    assert not be.analyze('listen.com').findings                   # anagrams of non-protected words are ignored
