# Presentation notes

**Problem:** A valid account can still perform risky actions such as downloading a large amount of confidential data or sharing it with an untrusted destination.

**Solution:** GUARD RAIL scans user-submitted text for configured sensitive patterns, scores simulated activity, logs explanations, and creates alerts for high-risk events.

**Workflow:** Activity/text → pattern scan → risk score → policy response → audit log → human review.

**Current prototype:** Flask web app, SQLite persistence, role-based demo login, text scanner, risk simulator, dashboard, activity logs, alert review.

**Honest AI statement:** The current risk engine is a transparent heuristic, not a trained model. Future work can add a trained anomaly detector using synthetic labeled data and measured evaluation.

**Demo success criteria:** A bulk external export should score higher than routine access; sensitive patterns should be explained; high-risk scenarios should create alerts; events should persist; admin should be able to mark alerts reviewed.
