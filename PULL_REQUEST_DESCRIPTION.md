# Pull Request: Fix tests, Pydantic defaults, DB logging, and URL parsing edge-cases

This branch fixes a failing test and several robustness issues in the backend:

- Implemented missing test body in backend/tests/test_rule_based.py to fix SyntaxError that broke the test suite.
- Added new tests for URLChecker edge-cases: backend/tests/test_url_checker.py
- Replaced shared mutable defaults in Pydantic models with Field(default_factory=...):
  - backend/app/models/scan.py
  - backend/app/models/url.py
- Improved scanning service error handling by logging exceptions during DB persistence (best-effort preserved): backend/app/services/scan_service.py
- Made URLChecker tolerant of scheme-less URLs by normalizing with http:// when netloc is empty and adjusted threshold for excessive subdomains: backend/app/analyzers/url_checker.py

Please review the changes and run the test suite. If you'd like, I can squash commits or adjust the PR description.
