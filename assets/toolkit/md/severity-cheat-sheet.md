# Severity Cheat Sheet

**Quick test:** *"If this fired against every user right now, unprompted, how bad is it?"*
→ that's roughly Critical/High. *"Only bad in an edge case or with victim interaction?"*
→ Medium/Low.

## Critical

Full account takeover, RCE, mass data exfiltration, admin bypass with no user interaction needed.

*Examples: SQLi that dumps the full user table with password hashes; unauthenticated RCE via file upload; auth bypass that logs you in as any user.*

## High

Significant data exposure, privilege escalation, auth bypass requiring some condition (e.g. a known username).

*Examples: IDOR that exposes other users' private data; privilege escalation from user to admin; SSRF reaching internal services.*

## Medium

Requires user interaction (CSRF, stored XSS needing a click), limited data exposure, or affects only the attacker's own account in an unintended way.

*Examples: CSRF on a state-changing action; stored XSS requiring an admin to view a specific page; reflected XSS requiring a crafted link.*

## Low

Info disclosure with minimal impact, missing best-practice headers, issues needing unrealistic preconditions.

*Examples: missing security headers; verbose error messages with no exploitable data; self-XSS.*

## Informational

Best-practice suggestions, no direct security impact.

*Examples: outdated library version with no known exploitable vulnerability; suggestions for defense-in-depth.*

---
*Part of the VulnCorp Helpdesk training toolkit.*
