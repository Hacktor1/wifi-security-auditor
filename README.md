# WiFi Security Auditor

A **WiFi network security auditing** tool written in Python. Scans WiFi networks, analyzes their security configurations, detects vulnerabilities, and generates detailed HTML audit reports.

## Features

* **WiFi Scanning** — Discovers nearby WiFi networks using system tools (`iw`, `nmcli`) with simulated fallback
* **Security Analysis** — Detects weak encryption (WEP, WPA), deprecated ciphers (TKIP), open networks, weak signals, and default SSIDs
* **Vulnerability Scoring** — Calculates risk scores (0-100) with severity levels (CRITICAL, HIGH, MEDIUM, LOW, SAFE)
* **HTML Reports** — Generates styled HTML audit reports with detailed findings and remediation recommendations
* **Configurable** — YAML config file for interface selection, thresholds, and output paths

## Project Structure

```
wifi-security-auditor/
├── config.yaml                 # Configuration file
├── README.md                   # This file
├── wifi_auditor/
│   ├── __init__.py             # Package initialization
│   ├── __main__.py             # CLI entry point
│   ├── scanner.py              # WiFi network scanner
│   ├── analyzer.py             # Security analysis engine
│   └── reporter.py             # HTML report generator
└── reports/                    # Generated audit reports (auto-created)
```

## Requirements & Dependencies

1. **Python**: Version 3.8 or higher
2. **Libraries**:
* `PyYAML` — Configuration parsing
* `Jinja2` — HTML report templating

3. **System tools** (optional, for real WiFi scanning):
* `iw` — Linux wireless tools
* `nmcli` — NetworkManager CLI
* `iwlist` — Legacy wireless scanner

Install the required libraries via terminal/CLI:

```bash
pip install pyyaml jinja2
```

## Setup and Running

### Quick Start (Simulated Mode)

```bash
python -m wifi_auditor --simulated
```

### Real WiFi Scanning

```bash
sudo python -m wifi_auditor --interface wlan0
```

### Full Options

```bash
python -m wifi_auditor [OPTIONS]

Options:
  -i, --interface TEXT   WiFi interface to use (default: wlan0)
  -s, --simulated        Use simulated WiFi networks
  -o, --output DIRECTORY Output directory for reports
  -c, --config FILE      Path to config YAML file
  -v, --verbose          Enable verbose output
```

## Security Checks

The analyzer performs the following vulnerability checks:

| Check | Severity | Description |
|-------|----------|-------------|
| Weak Encryption (WEP) | CRITICAL | WEP is trivially crackable |
| Open Network | CRITICAL | No encryption, traffic exposed |
| Outaded Encryption (WPA) | HIGH | Legacy WPA, vulnerable to TKIP attacks |
| Weak Cipher (TKIP) | HIGH | TKIP has known cryptographic weaknesses |
| Weak Cipher (WEP) | CRITICAL | WEP cipher is broken |
| Default SSID | MEDIUM | Indicates unmodified router settings |
| Hidden SSID | LOW | Obscurity without security |
| Weak Signal | INFO | Signal leaks beyond intended area |

## License

MIT
