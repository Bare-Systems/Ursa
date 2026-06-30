# Security Policy

Ursa is offensive-security software. Treat governance, approval, audit, and access-control behavior as first-class security requirements.

## Reporting

Report vulnerabilities privately with:

- affected subsystem
- operator or target impact
- reproduction steps
- expected versus actual approval, auth, or audit behavior

## Baseline Expectations

- High-risk workflows must stay approval-gated and auditable.
- Secrets, tokens, payload credentials, and real operator data must never be committed.
- Non-dev deployments must run with `environment: production` or `URSA_ENV=production`
  so startup validation rejects development defaults and missing API credentials.
- Deployment and public-surface changes must update `README.md` and `BLINK.md`.
