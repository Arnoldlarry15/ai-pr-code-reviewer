from ai_pr_reviewer import AIPrReviewer

sample_diff = """
diff --git a/src/auth.py b/src/auth.py
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,4 +10,12 @@
+AUTH_TOKEN = "MOCK_EXPOSED_SECRET_TOKEN_9988112233"
+def query_user(user_id):
+    query = f"SELECT * FROM users WHERE id = '{user_id}'"
+    return db.execute(query)
+
+async def sync_remote():
+    try:
+        await client.ping()
+    except:
+        pass
"""

print("Running AI PR Code Reviewer Demo...")
reviewer = AIPrReviewer()
report = reviewer.review_diff(sample_diff)

print("\n" + report.to_markdown())
print(f"\nProcessed {len(report.findings)} security/reliability findings.")
