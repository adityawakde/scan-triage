# Scan Triage Report

Total findings: 7

| Priority | Host | Port | Service | Version | Score | Why it matters |
|---|---|---|---|---|---|---|
| 1 | 192.168.1.20 | 23 | telnet | Linux telnetd | 80 | Telnet, cleartext login; Cleartext protocol |
| 2 | 192.168.1.10 | 3306 | mysql | MySQL 8.0.31 | 60 | MySQL exposed |
| 3 | 192.168.1.20 | 21 | ftp | vsftpd 3.0.3 | 50 | FTP, often cleartext; Cleartext protocol |
| 4 | 192.168.1.10 | 80 | http | Apache httpd 2.4.49 | 45 | Old version hint: Apache httpd 2.4.49 |
| 5 | 192.168.1.20 | 443 | https | nginx 1.22.0 | 15 | Open service, review exposure |
| 6 | 192.168.1.30 | 443 | https | nginx 1.22.0 | 15 | Open service, review exposure |
| 7 | 192.168.1.10 | 22 | ssh | OpenSSH 8.9p1 | 10 | Open service, review exposure |

## Suggested fix order

1. 192.168.1.20:23 (telnet) — close it, restrict it, or patch/upgrade it first.
2. 192.168.1.10:3306 (mysql) — close it, restrict it, or patch/upgrade it first.
3. 192.168.1.20:21 (ftp) — close it, restrict it, or patch/upgrade it first.
4. 192.168.1.10:80 (http) — close it, restrict it, or patch/upgrade it first.
5. 192.168.1.20:443 (https) — close it, restrict it, or patch/upgrade it first.
6. 192.168.1.30:443 (https) — close it, restrict it, or patch/upgrade it first.
7. 192.168.1.10:22 (ssh) — close it, restrict it, or patch/upgrade it first.
