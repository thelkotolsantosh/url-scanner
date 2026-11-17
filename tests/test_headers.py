from url_scanner.headers import analyze_headers, analyze_cookies, fingerprint_technology


def test_headers_ignore_case_and_report_missing_policies():
    report = analyze_headers({'Content-Security-Policy': "default-src 'self'"})
    assert 'content-security-policy' in report['present']
    assert 'strict-transport-security' in report['missing']


def test_cookie_flags_and_technology_hints():
    cookies = analyze_cookies(['PHPSESSID=sample; Secure; HttpOnly; SameSite=Lax'])
    assert cookies == [{'name': 'PHPSESSID', 'secure': True, 'httponly': True, 'samesite': 'Lax'}]
    assert fingerprint_technology({'Server': 'nginx'}, cookies) == ['server: nginx', 'PHP']
