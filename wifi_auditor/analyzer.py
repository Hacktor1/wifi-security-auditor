"""
WiFi Security Analyzer Module.

Analyzes scanned WiFi networks for security vulnerabilities and risks.
"""

import logging
from typing import List, Dict, Any
from dataclasses import asdict
from .scanner import WiFiNetwork

logger = logging.getLogger(__name__)


class Vulnerability:
    """Represents a detected vulnerability."""
    LEVELS = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def __init__(self, name: str, description: str, severity: str, recommendation: str):
        self.name = name
        self.description = description
        self.severity = severity if severity in self.LEVELS else "MEDIUM"
        self.recommendation = recommendation

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "recommendation": self.recommendation,
        }


# Weak ciphers and their risk levels
WEAK_CIPHERS = {
    "WEP": "CRITICAL",
    "TKIP": "HIGH",
    "WEP": "CRITICAL",
}

# Encryption types that are deprecated or insecure
UNSUPPORTED_ENCRYPTION = {"WEP": "CRITICAL", "WPA": "HIGH"}

# Default/weak passwords to check
DEFAULT_PASSWORDS = [
    "password", "admin", "12345678", "qwerty", "123456789",
    "letmein", "welcome", "monkey", "1234567", "abc12345",
    "password1", "1234567890", "00000000", "11111111",
]


class Analyzer:
    """Analyzes WiFi networks for security vulnerabilities."""

    def __init__(self, signal_threshold: int = -70):
        self.signal_threshold = signal_threshold

    def analyze(self, networks: List[WiFiNetwork]) -> List[Dict[str, Any]]:
        """Run full security analysis on a list of networks."""
        results = []
        for net in networks:
            vulnerabilities = self._check_network(net)
            risk_score = self._calculate_risk_score(net, vulnerabilities)
            results.append({
                "network": asdict(net),
                "vulnerabilities": [v.to_dict() for v in vulnerabilities],
                "risk_score": risk_score,
                "risk_level": self._risk_level(risk_score),
            })
        return results

    def _check_network(self, net: WiFiNetwork) -> List[Vulnerability]:
        """Run all vulnerability checks on a single network."""
        vulns = []

        # Check 1: Weak encryption
        vulns.extend(self._check_encryption(net))

        # Check 2: Weak cipher
        vulns.extend(self._check_cipher(net))

        # Check 3: Signal strength
        vulns.extend(self._check_signal(net))

        # Check 4: Open network
        vulns.extend(self._check_open_network(net))

        # Check 5: Default SSIDs (known router default names)
        vulns.extend(self._check_default_ssid(net))

        # Check 6: Hidden SSID detection (empty SSID)
        vulns.extend(self._check_hidden_ssid(net))

        return vulns

    def _check_encryption(self, net: WiFiNetwork) -> List[Vulnerability]:
        """Check if encryption type is weak or deprecated."""
        vulns = []
        if net.encryption == "WEP":
            vulns.append(Vulnerability(
                name="Weak Encryption (WEP)",
                description=f"Network '{net.ssid}' uses WEP encryption, which is trivially crackable in minutes using tools like aircrack-ng.",
                severity="CRITICAL",
                recommendation="Upgrade to WPA3 or at minimum WPA2 with a strong AES cipher suite."
            ))
        elif net.encryption == "WPA":
            vulns.append(Vulnerability(
                name="Outdated Encryption (WPA)",
                description=f"Network '{net.ssid}' uses legacy WPA encryption, vulnerable to TKIP-related attacks.",
                severity="HIGH",
                recommendation="Upgrade to WPA2 or WPA3 encryption on the router."
            ))
        return vulns

    def _check_cipher(self, net: WiFiNetwork) -> List[Vulnerability]:
        """Check if cipher is weak."""
        vulns = []
        if net.cipher == "TKIP":
            vulns.append(Vulnerability(
                name="Weak Cipher (TKIP)",
                description=f"Network '{net.ssid}' uses TKIP cipher, which has known cryptographic weaknesses.",
                severity="HIGH",
                recommendation="Switch to CCMP (AES) cipher suite."
            ))
        elif net.cipher == "WEP":
            vulns.append(Vulnerability(
                name="Weak Cipher (WEP)",
                description=f"Network '{net.ssid}' uses WEP cipher, which is broken and deprecated.",
                severity="CRITICAL",
                recommendation="Upgrade to AES/CCMP cipher with WPA2/WPA3."
            ))
        return vulns

    def _check_signal(self, net: WiFiNetwork) -> List[Vulnerability]:
        """Check if signal strength is weak (potential distance-based attack)."""
        vulns = []
        if net.signal < self.signal_threshold:
            vulns.append(Vulnerability(
                name="Weak Signal Strength",
                description=f"Network '{net.ssid}' has a weak signal ({net.signal} dBm), making it accessible from outside the intended coverage area.",
                severity="INFO",
                recommendation="Reduce transmission power or reposition the router to limit signal leakage."
            ))
        return vulns

    def _check_open_network(self, net: WiFiNetwork) -> List[Vulnerability]:
        """Check if network is open (no encryption)."""
        vulns = []
        if net.encryption == "OPEN":
            vulns.append(Vulnerability(
                name="Open Network (No Encryption)",
                description=f"Network '{net.ssid}' has no encryption, exposing all traffic to eavesdropping and MITM attacks.",
                severity="CRITICAL",
                recommendation="Enable WPA3 or WPA2 encryption with a strong password."
            ))
        return vulns

    def _check_default_ssid(self, net: WiFiNetwork) -> List[Vulnerability]:
        """Check if SSID matches known router default names."""
        DEFAULT_SSIDS = [
            "xfinitywifi", "attwifi", "linksys", "netgear", "tplink",
            "dlink", "asus", "wifi", "default", "home",
            "WIFI-5", "NETGEAR", "TP-LINK_2.4", "MiFi",
        ]

        vulns = []
        ssid_lower = net.ssid.lower().strip()
        for default in DEFAULT_SSIDS:
            if default.lower() in ssid_lower:
                vulns.append(Vulnerability(
                    name="Default SSID Detected",
                    description=f"Network SSID '{net.ssid}' matches a common router default name, indicating the owner may not have changed default settings.",
                    severity="MEDIUM",
                    recommendation="Rename the SSID and disable SSID broadcast if not needed."
                ))
                break
        return vulns

    def _check_hidden_ssid(self, net: WiFiNetwork) -> List[Vulnerability]:
        """Check if SSID is empty (hidden network)."""
        vulns = []
        if not net.ssid or net.ssid == "<HIDDEN>" or len(net.ssid.strip()) == 0:
            vulns.append(Vulnerability(
                name="Hidden SSID",
                description="Network SSID is hidden. While this provides obscurity, it does not provide security and can be revealed with passive monitoring.",
                severity="LOW",
                recommendation="Use proper encryption instead of relying on SSID hiding."
            ))
        return vulns

    def _calculate_risk_score(self, net: WiFiNetwork, vulns: List[Vulnerability]) -> int:
        """Calculate a numeric risk score (0-100)."""
        SEVERITY_WEIGHTS = {
            "INFO": 5,
            "LOW": 10,
            "MEDIUM": 20,
            "HIGH": 30,
            "CRITICAL": 50,
        }

        score = 0
        for v in vulns:
            score += SEVERITY_WEIGHTS.get(v.severity, 10)

        # Signal-based penalty
        if net.signal < -80:
            score += 5
        elif net.signal < -70:
            score += 3

        return min(score, 100)

    def _risk_level(self, score: int) -> str:
        """Convert numeric score to risk level label."""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        return "SAFE"
