import backend_source_scan as scan


def test_secret_patterns_detect_realistic_tokens_without_matching_placeholders():
    realistic = b"sk_" + b"live_" + b"abcdefghijklmnopqrstuvwxyz"
    placeholder = b"sk_" + b"live_" + b"xxx"
    private_key = b"-----BEGIN " + b"PRIVATE KEY-----"
    assert scan.SECRET_PATTERNS["stripe_secret"].search(realistic)
    assert not scan.SECRET_PATTERNS["stripe_secret"].search(placeholder)
    assert scan.SECRET_PATTERNS["private_key"].search(private_key)
