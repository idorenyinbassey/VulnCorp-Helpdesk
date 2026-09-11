# Safe Testing Rules

**VulnCorp Helpdesk / Bug Bounty — Rules of Engagement**

## Before You Test Anything

- [ ] I have explicit written authorization for this target
- [ ] I have read the program's scope page in full (not skimmed)
- [ ] I know what's OUT of scope, not just what's in
- [ ] I know the safe harbor terms (am I protected from legal action?)

## While Testing

- [ ] Stay inside listed scope — no "just checking" adjacent domains
- [ ] No automated scanners at full throttle without checking rate-limit rules
- [ ] No DoS, no destructive testing (mass account creation, data deletion at scale)
- [ ] Stop and ask if you find something that could affect other users' live data
- [ ] Never access more data than needed to prove a finding (one record, not the table)
- [ ] No social engineering unless explicitly in scope
- [ ] Use your own test accounts — never a real user's, even if "just to check"

## If You Find Something Serious

- [ ] Stop testing that specific vector immediately
- [ ] Report it right away — don't keep poking to "make sure"
- [ ] Never publicly disclose before the program's disclosure window closes

## Red Lines (never do these, in-scope or not)

- Never pivot from a web bug into someone's personal device/data
- Never exfiltrate more than a proof-of-concept sample
- Never test against production data you weren't explicitly told you could touch

---
*Part of the VulnCorp Helpdesk training toolkit — for use in authorized lab and bug bounty contexts only.*
