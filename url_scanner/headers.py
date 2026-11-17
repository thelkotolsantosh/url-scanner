"""Summarize response headers, cookie flags, and advertised technologies."""

from http.cookies import SimpleCookie

SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "x-frame-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-embedder-policy",
)


def analyze_headers(headers):
    values = {key.lower(): value for key, value in headers.items()}
    present = {key: values[key] for key in SECURITY_HEADERS if values.get(key)}
    missing = [key for key in SECURITY_HEADERS if key not in present]
    score = len(present) / len(SECURITY_HEADERS)
    grade = "A" if score == 1 else "B" if score >= .75 else "C" if score >= .5 else "D" if score >= .25 else "F"
    return {"grade": grade, "present": present, "missing": missing,
            "note": "Presence check only; header policies are not validated."}


def analyze_cookies(set_cookie_headers):
    results = []
    for value in set_cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(value)
        except Exception:
            continue
        for name, morsel in cookie.items():
            results.append({"name": name, "secure": bool(morsel["secure"]),
                            "httponly": bool(morsel["httponly"]),
                            "samesite": morsel["samesite"] or None})
    return results


def fingerprint_technology(headers, cookies):
    values = {key.lower(): value for key, value in headers.items()}
    hints = [f"{key}: {values[key]}" for key in ("server", "x-powered-by") if values.get(key)]
    known = {"phpsessid": "PHP", "jsessionid": "Java", "csrftoken": "Django",
             "laravel_session": "Laravel", "_shopify_y": "Shopify"}
    for cookie in cookies:
        hint = known.get(cookie["name"].lower())
        if hint and hint not in hints:
            hints.append(hint)
    return hints
