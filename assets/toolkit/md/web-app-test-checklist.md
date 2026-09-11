# Web App Test Checklist

**Target:** _______________   **Date:** _______________   **Tester:** _______________

| # | Category | Tested? | Result | Severity | Notes |
|---|---|---|---|---|---|
| 1 | Injection — SQLi, XSS (reflected/stored/DOM), SSTI, command injection, XXE, NoSQLi | ☐ | | | |
| 2 | Broken Auth — default creds, password reset flaws, 2FA bypass, session fixation, JWT issues | ☐ | | | |
| 3 | Access Control — IDOR, horizontal/vertical privilege escalation, forced browsing, BOLA | ☐ | | | |
| 4 | Business Logic — race conditions, workflow bypass, price manipulation, coupon abuse | ☐ | | | |
| 5 | File Upload — web shells, extension bypass, path traversal, content-type spoofing | ☐ | | | |
| 6 | SSRF — internal IP access, cloud metadata (169.254.169.254), protocol smuggling | ☐ | | | |
| 7 | CSRF — missing/weak tokens, method change (POST→GET) | ☐ | | | |
| 8 | Info Disclosure — exposed .git/.env, verbose errors, API keys in source, directory listing | ☐ | | | |
| 9 | Misconfig — CORS, security headers, open redirects, verbose errors, debug endpoints | ☐ | | | |
| 10 | API-specific — mass assignment, broken object-level auth, rate limiting, GraphQL introspection | ☐ | | | |
| 11 | Client-side — clickjacking, DOM XSS, prototype pollution, postMessage flaws | ☐ | | | |
| 12 | Advanced — HTTP smuggling, deserialization, host header injection, cache poisoning | ☐ | | | |

**Overall notes:** ___________________________________________________

---
*Part of the VulnCorp Helpdesk training toolkit.*
