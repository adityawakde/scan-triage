#!/usr/bin/env python3
"""
scan-triage: turn raw Nmap / Nessus scan output into a prioritised fix list.

Built in Kali Linux with Python (standard library only).

Usage:
    python3 triage.py scan.xml
    python3 triage.py scan.xml -o report.md
    python3 triage.py scan.xml --nessus nessus.csv -o report.md

What it does:
  1. Parses Nmap XML (-oX) with xml.etree.ElementTree.
  2. Optionally parses a Nessus CSV export and merges matching findings.
  3. Deduplicates findings by (host, port, service).
  4. Scores each finding with a transparent, rule-based risk score:
     risky service/port + exposed database/cache + old version hints.
  5. Writes a prioritised Markdown report, highest risk first.

This is a triage helper, not a replacement for a full scanner.
Only scan networks you own or have permission to test.
"""

import argparse
import csv
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

# Services/ports that raise risk when exposed, with a plain-language reason.
RISKY_PORTS = {
    21: ("FTP, often cleartext", 40),
    23: ("Telnet, cleartext login", 70),
    445: ("SMB, common lateral-movement target", 50),
    1433: ("MSSQL exposed", 50),
    3306: ("MySQL exposed", 50),
    5432: ("PostgreSQL exposed", 50),
    6379: ("Redis, often unauthenticated if exposed", 60),
    27017: ("MongoDB exposed", 60),
    5900: ("VNC, remote desktop", 50),
}

# Very old / known-weak version hints (exact CVE matching is out of scope).
OLD_VERSION_HINTS = ["2.4.49", "2.2.", "1.0", "vsftpd 2.3.4"]


def score_finding(port, service, version):
    """Return (score 0-100, reasons list). Scoring is rule-based and visible."""
    score = 10
    reasons = []
    if port in RISKY_PORTS:
        label, points = RISKY_PORTS[port]
        score += points
        reasons.append(label)
    if service in ("ftp", "telnet"):
        reasons.append("Cleartext protocol")
    if version:
        for hint in OLD_VERSION_HINTS:
            if hint in version:
                score += 30
                reasons.append(f"Old version hint: {version}")
                break
    if port in (80, 443):
        score += 5
    return min(score, 100), reasons


def parse_nmap(path):
    """Parse Nmap XML into a list of finding dicts."""
    root = ET.parse(path).getroot()
    findings = []
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else "unknown"
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            port = int(port_el.get("portid"))
            service_el = port_el.find("service")
            service = service_el.get("name", "") if service_el is not None else ""
            version = ""
            if service_el is not None:
                product = service_el.get("product", "")
                ver = service_el.get("version", "")
                version = f"{product} {ver}".strip()
            score, reasons = score_finding(port, service, version)
            findings.append({
                "host": host_ip,
                "port": port,
                "service": service,
                "version": version,
                "score": score,
                "reasons": reasons,
                "source": "nmap",
            })
    return findings


def parse_nessus_csv(path):
    """Parse a Nessus CSV export, if one is supplied. Best-effort: skips
    files without the expected columns instead of crashing."""
    findings = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return findings
        # Normalise header names so exports with different cases still work.
        field_map = {name.strip().lower(): name for name in reader.fieldnames}
        needed = {"host", "port", "name", "severity"}
        if not needed.issubset(field_map):
            return findings
        severity_score = {"critical": 90, "high": 70, "medium": 40, "low": 15, "info": 5}
        for row in reader:
            def get(key):
                return (row.get(field_map[key], "") or "").strip()
            sev = get("severity").lower()
            findings.append({
                "host": get("host"),
                "port": int(get("port")) if get("port").isdigit() else 0,
                "service": get("name"),
                "version": "",
                "score": severity_score.get(sev, 10),
                "reasons": [f"Nessus severity: {get('severity')}"],
                "source": "nessus",
            })
    return findings


def deduplicate(findings):
    """Keep the highest-scoring entry per (host, port, service)."""
    best = {}
    for item in findings:
        key = (item["host"], item["port"], item["service"])
        if key not in best or item["score"] > best[key]["score"]:
            best[key] = item
    return sorted(best.values(), key=lambda x: x["score"], reverse=True)


def render_markdown(findings):
    lines = ["# Scan Triage Report", ""]
    lines.append(f"Total findings: {len(findings)}")
    lines.append("")
    lines.append("| Priority | Host | Port | Service | Version | Score | Why it matters |")
    lines.append("|---|---|---|---|---|---|---|")
    for i, item in enumerate(findings, 1):
        why = "; ".join(item["reasons"]) or "Open service, review exposure"
        lines.append(
            f"| {i} | {item['host']} | {item['port']} | {item['service']} "
            f"| {item['version']} | {item['score']} | {why} |"
        )
    lines.append("")
    lines.append("## Suggested fix order")
    lines.append("")
    for i, item in enumerate(findings[:10], 1):
        lines.append(
            f"{i}. {item['host']}:{item['port']} ({item['service']}) — "
            f"close it, restrict it, or patch/upgrade it first."
        )
    lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Prioritise Nmap/Nessus scan output.")
    parser.add_argument("scan", help="Nmap XML file (nmap -oX scan.xml ...)")
    parser.add_argument("--nessus", help="Optional Nessus CSV export")
    parser.add_argument("-o", "--output", help="Output Markdown file (default: stdout)")
    args = parser.parse_args(argv)

    findings = parse_nmap(args.scan)
    if args.nessus:
        findings += parse_nessus_csv(args.nessus)
    findings = deduplicate(findings)
    report = render_markdown(findings)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Wrote {args.output} with {len(findings)} findings.")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
