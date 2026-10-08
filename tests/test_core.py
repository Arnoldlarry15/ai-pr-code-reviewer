from ai_pr_reviewer import AIPrReviewer

def test_clean_diff():
    clean_diff = """
+++ b/src/math.py
@@ -1,2 +1,3 @@
+def add(a: int, b: int) -> int:
+    return a + b
"""
    reviewer = AIPrReviewer()
    report = reviewer.review_diff(clean_diff)
    assert report.verdict == "APPROVE"
    assert report.risk_score == "LOW"
    assert len(report.findings) == 0

def test_vulnerable_diff():
    vuln_diff = """
+++ b/src/api.py
@@ -5,3 +5,6 @@
+AUTH_TOKEN = "MOCK_EXPOSED_SECRET_TOKEN_1234567890"
+def get_user(uid):
+    return db.execute(f"SELECT * FROM u WHERE id = '{uid}'")
"""
    reviewer = AIPrReviewer()
    report = reviewer.review_diff(vuln_diff)
    assert report.verdict == "REQUEST_CHANGES"
    assert report.risk_score in ("HIGH", "CRITICAL")
    assert len(report.findings) >= 2
