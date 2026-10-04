"""
Unit tests for app/urlcheck.py (string-only heuristics)
"""

from app.urlcheck import analyze_url_string, is_official_domain, extract_urls


def test_official_domains():
    assert is_official_domain("sebi.gov.in")
    assert is_official_domain("www.sebi.gov.in")
    assert is_official_domain("siportal.sebi.gov.in")
    assert is_official_domain("scores.sebi.gov.in")
    assert is_official_domain("nseindia.com")
    assert is_official_domain("cybercrime.gov.in")
    assert not is_official_domain("sebi-scam.xyz")
    assert not is_official_domain("fake-nsdl.com")


def test_ip_host_detected():
    sigs, _ = analyze_url_string("http://192.168.1.100/trade")
    assert any(s["id"] == "URL_IP_HOST" for s in sigs)


def test_punycode_detected():
    sigs, _ = analyze_url_string("https://xn--seb-10a.gov.in/portal")
    assert any(s["id"] == "URL_PUNYCODE" for s in sigs)


def test_url_shortener_detected():
    sigs, _ = analyze_url_string("http://bit.ly/doubler")
    assert any(s["id"] == "URL_SHORTENER" for s in sigs)


def test_suspicious_tld_detected():
    sigs, _ = analyze_url_string("http://invest-profit.xyz/join")
    assert any(s["id"] == "URL_SUSPICIOUS_TLD" for s in sigs)


def test_no_https_detected():
    sigs, _ = analyze_url_string("http://random-finance-blog.com")
    assert any(s["id"] == "URL_NO_HTTPS" for s in sigs)


def test_finance_keyword_misuse():
    sigs, _ = analyze_url_string("https://vip-trade-profit-crypto.net")
    assert any(s["id"] == "URL_FINANCE_KEYWORD_MISUSE" for s in sigs)


def test_brand_impersonation():
    sigs, _ = analyze_url_string("https://sebi-verification-check.com")
    assert any(s["id"] == "URL_BRAND_IMPERSONATION" for s in sigs)


def test_extract_urls_from_text():
    text = "Visit http://fake-crypto.xyz and register at https://www.sebi.gov.in today"
    urls = extract_urls(text)
    assert len(urls) >= 2
