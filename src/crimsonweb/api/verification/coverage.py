"""OWASP 2025 awareness mapping; never claims full category coverage."""

from .models import Top10Coverage

TOP10 = (
    ("A01", "Broken Access Control"), ("A02", "Security Misconfiguration"),
    ("A03", "Software Supply Chain Failures"), ("A04", "Cryptographic Failures"),
    ("A05", "Injection"), ("A06", "Insecure Design"),
    ("A07", "Authentication Failures"), ("A08", "Software or Data Integrity Failures"),
    ("A09", "Security Logging and Alerting Failures"),
    ("A10", "Mishandling of Exceptional Conditions"),
)
MAPPING = {
    "bola_cross_owner_read": {"A01"},
    "web_security_observation": {"A02"},
    "xss_reflection_probe": {"A05"},
    "sql_error_probe": {"A05", "A10"},
}


def coverage_for(tests, evidence):
    tls_tests = {e.test_id for e in evidence if "negotiated_tls_observed" in getattr(e, "signals", [])}
    cookie_tests = {e.test_id for e in evidence if "cookie_attributes_observed" in getattr(e, "signals", [])}
    rows = []
    for category, title in TOP10:
        matching = [t.id for t in tests if t.status == "completed" and t.outcome != "inconclusive"
                    and (category in MAPPING.get(t.catalog_id, set())
                         or category == "A04" and t.id in tls_tests
                         or category == "A07" and t.id in cookie_tests)]
        rows.append(Top10Coverage(
            category=category, title=title,
            status="partially_assessed" if matching else "not_tested", test_ids=matching,
            limitations=["category_not_exhaustively_tested"] if matching else ["requires_additional_authorized_evidence"],
        ))
    return rows
