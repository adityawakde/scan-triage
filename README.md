# Scan Triage

A small Python tool built in Kali Linux that turns raw Nmap (and optionally Nessus) scan output into a prioritised fix list.

Raw scanner output is noisy. This tool answers the practical question: **what should I fix first?**

## What it does

- Parses Nmap XML output (`nmap -oX scan.xml ...`)
- Optionally merges a Nessus CSV export
- Deduplicates findings by host, port, and service
- Scores each finding with a transparent rule-based system:
  - risky exposed services (Telnet, FTP, databases, Redis, MongoDB, SMB)
  - cleartext protocols
  - old version hints
- Outputs a prioritised Markdown report with a suggested fix order

## Techniques used

- Python 3, standard library only — no dependencies to install
- `xml.etree.ElementTree` for Nmap XML parsing
- `csv` / `DictReader` for Nessus CSV parsing
- Rule-based risk scoring and deduplication
- CLI built with `argparse`

## How to run (Kali Linux)

```bash
# 1. Scan a network you own or have permission to test
nmap -sV -oX scan.xml 192.168.1.0/24

# 2. Triage the results
python3 triage.py scan.xml -o report.md

# 3. With a Nessus export as well
python3 triage.py scan.xml --nessus nessus.csv -o report.md
```

Try it without a real scan first:

```bash
python3 triage.py sample_scan.xml -o sample_report.md
```

## Example output

See `sample_report.md` — Telnet and exposed MySQL rank above ordinary web services, which is the whole point.

## Why this project

This is the starting point for my Meta Global AI Developer Hackathon project: an AI copilot that takes this same triage output and turns it into plain-language explanations and remediation plans using Meta's models.

## Safety note

Only scan networks you own or have explicit permission to test.
