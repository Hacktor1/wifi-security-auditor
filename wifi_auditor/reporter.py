"""
WiFi Security Audit Report Generator.

Generates HTML reports from security analysis results.
"""

import os
import html
import logging
from datetime import datetime
from typing import List, Dict, Any
from jinja2 import Template

logger = logging.getLogger(__name__)

# CSS styling
STYLES = """
    * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background: #0a0a0a;
        color: #e0e0e0;
        padding: 20px;
    }
    .container {
        max-width: 1200px;
        margin: 0 auto;
    }
    h1 {
        text-align: center;
        color: #00ff88;
        margin-bottom: 30px;
        font-size: 2.5em;
        text-shadow: 0 0 15px rgba(0, 255, 136, 0.3);
    }
    .summary {
        display: flex;
        gap: 20px;
        margin-bottom: 30px;
        flex-wrap: wrap;
    }
    .stat-card {
        background: #1a1a1a;
        border-radius: 10px;
        padding: 20px;
        flex: 1;
        min-width: 180px;
        text-align: center;
        border: 1px solid #333;
    }
    .stat-card .label {
        font-size: 0.9em;
        color: #888;
        margin-bottom: 10px;
    }
    .stat-card .value {
        font-size: 2em;
        font-weight: bold;
    }
    .stat-card.critical .value { color: #ff4444; }
    .stat-card.high .value { color: #ff8800; }
    .stat-card.medium .value { color: #ffbb33; }
    .stat-card.low .value { color: #00aaff; }
    .stat-card.safe .value { color: #00ff88; }
    .timestamp {
        text-align: center;
        color: #666;
        margin-bottom: 30px;
    }
    .network-card {
        background: #1a1a1a;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 15px;
        border-left: 4px solid #333;
    }
    .network-card.critical { border-left-color: #ff4444; }
    .network-card.high { border-left-color: #ff8800; }
    .network-card.medium { border-left-color: #ffbb33; }
    .network-card.low { border-left-color: #00aaff; }
    .network-card.safe { border-left-color: #00ff88; }
    .network-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 15px;
    }
    .network-title {
        font-size: 1.4em;
        font-weight: bold;
        color: #fff;
    }
    .network-meta {
        display: flex;
        gap: 15px;
        margin-bottom: 10px;
        font-size: 0.9em;
    }
    .meta-item {
        color: #aaa;
    }
    .meta-item strong {
        color: #ccc;
    }
    .risk-badge {
        padding: 5px 15px;
        border-radius: 20px;
        font-weight: bold;
        font-size: 0.85em;
        text-transform: uppercase;
    }
    .risk-badge.critical { background: #ff4444; color: #fff; }
    .risk-badge.high { background: #ff8800; color: #fff; }
    .risk-badge.medium { background: #ffbb33; color: #000; }
    .risk-badge.low { background: #00aaff; color: #fff; }
    .risk-badge.safe { background: #00aa00; color: #fff; }
    .vulnerabilities {
        margin-top: 15px;
    }
    .vuln-item {
        background: #222;
        border-radius: 8px;
        padding: 12px;
        margin-bottom: 8px;
    }
    .vuln-title {
        color: #ff8888;
        font-weight: bold;
        margin-bottom: 5px;
    }
    .vuln-severity {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 12px;
        font-size: 0.75em;
        font-weight: bold;
        margin-left: 10px;
    }
    .vuln-severity.CRITICAL { background: #ff4444; color: #fff; }
    .vuln-severity.HIGH { background: #ff8800; color: #fff; }
    .vuln-severity.MEDIUM { background: #ffbb33; color: #000; }
    .vuln-severity.LOW { background: #00aaff; color: #fff; }
    .vuln-severity.INFO { background: #555; color: #fff; }
    .vuln-desc {
        color: #aaa;
        font-size: 0.9em;
        margin: 5px 0;
    }
    .vuln-rec {
        color: #88ff88;
        font-size: 0.85em;
        margin-top: 5px;
    }
    .no-vulns {
        color: #00ff88;
        text-align: center;
        padding: 20px;
    }
    footer {
        text-align: center;
        margin-top: 40px;
        color: #555;
        font-size: 0.85em;
    }
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Security Audit Report</title>
    <style>{{ styles }}</style>
</head>
<body>
<div class="container">
    <h1>🛡️ WiFi Security Audit Report</h1>
    <div class="timestamp">Generated: {{ generated_at }}</div>

    <div class="summary">
        <div class="stat-card safe">
            <div class="label">Networks Scanned</div>
            <div class="value">{{ summary.total_networks }}</div>
        </div>
        <div class="stat-card critical">
            <div class="label">Critical</div>
            <div class="value">{{ summary.critical }}</div>
        </div>
        <div class="stat-card high">
            <div class="label">High</div>
            <div class="value">{{ summary.high }}</div>
        </div>
        <div class="stat-card medium">
            <div class="label">Medium</div>
            <div class="value">{{ summary.medium }}</div>
        </div>
        <div class="stat-card safe">
            <div class="label">Safe Networks</div>
            <div class="value">{{ summary.safe }}</div>
        </div>
    </div>

    {% for result in results %}
    {% set net = result.network %}
    <div class="network-card {{ result.risk_level|lower }}">
        <div class="network-header">
            <span class="network-title">{{ net.ssid }}</span>
            <span class="risk-badge {{ result.risk_level|lower }}">{{ result.risk_level }}</span>
        </div>
        <div class="network-meta">
            <span class="meta-item"><strong>BSSID:</strong> {{ net.bssid }}</span>
            <span class="meta-item"><strong>Signal:</strong> {{ net.signal }} dBm</span>
            <span class="meta-item"><strong>Freq:</strong> {{ net.frequency }} MHz</span>
            <span class="meta-item"><strong>Channel:</strong> {{ net.channel }}</span>
            <span class="meta-item"><strong>Encryption:</strong> {{ net.encryption }}</span>
            <span class="meta-item"><strong>Cipher:</strong> {{ net.cipher }}</span>
        </div>
        <div class="network-meta">
            <span class="meta-item"><strong>Risk Score:</strong> {{ result.risk_score }}/100</span>
            <span class="meta-item"><strong>Vulnerabilities:</strong> {{ result.vulnerabilities|length }}</span>
        </div>

        {% if result.vulnerabilities %}
        <div class="vulnerabilities">
            {% for vuln in result.vulnerabilities %}
            <div class="vuln-item">
                <span class="vuln-title">{{ vuln.name }}</span>
                <span class="vuln-severity {{ vuln.severity }}">{{ vuln.severity }}</span>
                <div class="vuln-desc">{{ vuln.description }}</div>
                <div class="vuln-rec">🔧 {{ vuln.recommendation }}</div>
            </div>
            {% endfor %}
        </div>
        {% else %}
        <div class="no-vulns">✅ No vulnerabilities detected for this network.</div>
        {% endif %}
    </div>
    {% endfor %}

    <footer>
        WiFi Security Auditor v1.0.0 | Generated by automated security audit
    </footer>
</div>
</body>
</html>"""


class Reporter:
    """Generates HTML reports from security analysis results."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir

    def generate(self, results: List[Dict[str, Any]]) -> str:
        """Generate an HTML report and return the file path."""
        os.makedirs(self.output_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"wifi_audit_report_{timestamp}.html"
        filepath = os.path.join(self.output_dir, filename)

        # Calculate summary stats
        summary = self._calculate_summary(results)

        # Render HTML
        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            styles=STYLES,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            results=results,
            summary=summary,
        )

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"Report generated: {filepath}")
        return filepath

    def _calculate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate summary statistics for the report."""
        summary = {
            "total_networks": len(results),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "safe": 0,
        }

        for result in results:
            level = result["risk_level"]
            if level == "CRITICAL":
                summary["critical"] += 1
            elif level == "HIGH":
                summary["high"] += 1
            elif level == "MEDIUM":
                summary["medium"] += 1
            elif level == "LOW":
                summary["low"] += 1
            else:
                summary["safe"] += 1

        return summary
