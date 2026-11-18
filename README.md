# Phishing Email Forensics: Header Analysis & SPF/DKIM/DMARC Detection

A small Python tool that analyzes raw `.eml` files, scores each email from 0 to 100 and labels it **PHISHING / SUSPICIOUS / CLEAN**. It was built for a phishing email forensics project (course IAO202, FPT University) and focuses on cases where **authentication passes but the email is still malicious**.

## What it does

For every `.eml` file the script parses the headers and body, applies rule-based checks and produces a console report, `results.json` and an HTML report (`phishing_report.html`).

| Check | Points | What it looks for |
|---|---|---|
| Authentication | 5 to 25 | DMARC fail, missing/failed DKIM, failed inner `Received-SPF` (relay abuse), missing DMARC |
| Domain spoofing | 25 | `From` uses the recipient's own domain without a passing DMARC |
| Brand impersonation | 20 | Display name or subject mentions Microsoft, Chase or DocuSign but the sending domain does not belong to that brand |
| Header mismatch | 10 each | `Reply-To` or `Return-Path` domain differs from the `From` domain |
| Suspicious domain | 10 to 15 | Random-looking burner domains and random envelope senders |
| Malicious URLs | up to 30 | Abused hosting/CDN (S3, CloudFront...), risky TLDs, victim email embedded in the URL (plain or base64), fake-brand keywords |
| Content | up to 15 | Urgency and credential keywords (`verify`, `suspend`, `password`...) |
| Attachments | 5 | Suspicious attachments |

Verdict thresholds: **score >= 50 = PHISHING**, **25 to 49 = SUSPICIOUS**, **below 25 = CLEAN**.

## Results on the 5 sample emails

| Sample | Technique | SPF / DKIM / DMARC | Original spam filter | Score | Verdict |
|---|---|---|---|---|---|
| `1_cloud_s3_docusign.eml` | Cloud storage abuse (DocuSign lure) | pass / pass / pass | Missed (0.40) | 50 | PHISHING |
| `2_burner_chase.eml` | Newly registered burner domain (Chase lure) | pass / pass / pass | Caught (13.78) | 85 | PHISHING |
| `3_direct_spoof_monkey.eml` | Direct spoof of the recipient's domain | pass / none / fail | Missed (1.40) | 100 | PHISHING |
| `4_replyto_docusign.eml` | Reply-To abuse (DocuSign lure) | pass / pass / pass | Missed (4.80) | 64 | PHISHING |
| `5_o365_relay_abuse.eml` | Microsoft 365 relay abuse | pass / none / none (inner SPF fail) | Missed (8.20) | 80 | PHISHING |

Key finding: **3 of 5 emails passed SPF, DKIM and DMARC** and still were phishing, and the original spam filter caught only **1 of 5**. Authentication results alone are not enough to trust an email.

## How to run

Requires Python 3 only (standard library, no `pip install` needed).

```bash
# Option 1: helper script (Git Bash, Kali Linux, macOS)
bash run_demo.sh

# Option 2: run directly
python3 phish_demo.py *.eml
```

Output: a colored console report, `results.json` and `phishing_report.html`.

## Project structure

```
phish_demo.py          # analyzer (parsing, scoring, reports)
run_demo.sh            # finds Python, runs the analyzer, opens the HTML report
*.eml                  # 5 sample phishing emails
results.json           # sample output
phishing_report.html   # sample HTML report
```

## Limitations

- Tested only on 5 phishing samples and **no legitimate emails**, so the false positive rate is unknown.
- Rules and weights were tuned by hand on these samples (for example the brand list, risky TLDs and some URL patterns), so they will not generalize to every campaign.
- Static analysis only: URLs are not visited and no reputation lookups (VirusTotal, PhishTank) are made.

## Suggested SOC mitigations

- Staged DMARC enforcement (`p=none` to `quarantine` to `reject`).
- Quarantine mail from domains registered in the last 30 days.
- Tag external senders with an `[EXTERNAL]` banner.
- Centralize mail logs in a SIEM (for example via rsyslog).

## Disclaimer

The `.eml` files are real phishing samples kept for educational purposes. Do not click links or open attachments inside them.

## Author

Mai Le Anh Thu, Information Assurance student, FPT University.
