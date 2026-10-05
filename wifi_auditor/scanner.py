"""
WiFi Network Scanner Module.

Responsible for discovering WiFi networks using system tools (iw/nmcli)
with a simulated fallback for environments without WiFi hardware.
"""

import subprocess
import re
import logging
import shutil
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

@dataclass
class WiFiNetwork:
    """Represents a discovered WiFi network."""
    ssid: str
    bssid: str
    signal: int  # dBm, negative values (e.g., -50, -70)
    frequency: float  # MHz
    encryption: str  # 'WPA2', 'WPA3', 'WEP', 'OPEN'
    cipher: str
    channel: int
    timestamp: str = ""

logger = logging.getLogger(__name__)

# Simulated networks for fallback mode
SIMULATED_NETWORKS = [
    WiFiNetwork(
        ssid="HomeNetwork",
        bssid="00:11:22:33:44:55",
        signal=-45,
        frequency=2437.0,
        encryption="WPA2",
        cipher="CCMP",
        channel=6,
    ),
    WiFiNetwork(
        ssid="Free_Public_WiFi",
        bssid="AA:BB:CC:DD:EE:FF",
        signal=-72,
        frequency=5180.0,
        encryption="OPEN",
        cipher="NONE",
        channel=36,
    ),
    WiFiNetwork(
        ssid="OfficeSecure",
        bssid="12:34:56:78:9A:BC",
        signal=-55,
        frequency=5240.0,
        encryption="WPA3",
        cipher="CCMP",
        channel=44,
    ),
    WiFiNetwork(
        ssid="Legacy_Device",
        bssid="DE:AD:BE:EF:CA:FE",
        signal=-68,
        frequency=2462.0,
        encryption="WEP",
        cipher="WEP",
        channel=11,
    ),
    WiFiNetwork(
        ssid="Guest_Network",
        bssid="01:23:45:67:89:AB",
        signal=-78,
        frequency=2412.0,
        encryption="WPA2",
        cipher="TKIP",
        channel=1,
    ),
    WiFiNetwork(
        ssid="Neighbor_WiFi",
        bssid="FE:DC:BA:98:76:54",
        signal=-85,
        frequency=5500.0,
        encryption="WPA2",
        cipher="CCMP",
        channel=100,
    ),
]


class Scanner:
    """WiFi network scanner with real and simulated modes."""

    def __init__(self, interface: str = "wlan0", use_simulated: bool = True):
        self.interface = interface
        self.use_simulated = use_simulated
        self._check_tools()

    def _check_tools(self) -> bool:
        """Check if system WiFi tools are available."""
        tools = ["iw", "nmcli"]
        available = []
        for tool in tools:
            if shutil.which(tool):
                available.append(tool)
        if available:
            logger.info(f"Available WiFi tools: {', '.join(available)}")
        else:
            logger.warning("No WiFi tools found; will use simulated data")
        return len(available) > 0

    def scan_real(self) -> List[WiFiNetwork]:
        """Attempt a real WiFi scan using system tools."""
        networks = []
        # Try nmcli first (more common on modern Linux)
        if shutil.which("nmcli"):
            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,FREQ,SECURITY,CHAN", "dev", "wifi", "list"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and result.stdout.strip():
                    for line in result.stdout.strip().split("\n"):
                        parts = line.split(":")
                        if len(parts) >= 6:
                            ssid = parts[0]
                            bssid = parts[1]
                            signal = -int(parts[2]) if parts[2].isdigit() else -50
                            freq = float(parts[3]) / 1000.0  # convert MHz to GHz representation
                            security = parts[4]
                            channel = int(parts[5]) if parts[5].isdigit() else 1
                            encryption = self._parse_security(security)
                            cipher = "CCMP" if encryption != "OPEN" else "NONE"
                            networks.append(WiFiNetwork(
                                ssid=ssid,
                                bssid=bssid,
                                signal=signal,
                                frequency=freq * 1000,  # store as MHz
                                encryption=encryption,
                                cipher=cipher,
                                channel=channel,
                                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            ))
                    if networks:
                        return networks
            except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                logger.error(f"nmcli scan failed: {e}")

        # Try iw as fallback
        if shutil.which("iw"):
            try:
                result = subprocess.run(
                    ["iw", self.interface, "scan"],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    networks = self._parse_iw_output(result.stdout)
                    if networks:
                        return networks
            except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
                logger.error(f"iw scan failed: {e}")

        return networks

    def _parse_security(self, security_str: str) -> str:
        """Parse nmcli security string into encryption type."""
        security_str = security_str.upper()
        if "WPA3" in security_str:
            return "WPA3"
        elif "WPA2" in security_str:
            return "WPA2"
        elif "WEP" in security_str:
            return "WEP"
        elif "WPA" in security_str:
            return "WPA"
        return "OPEN"

    def _parse_iw_output(self, output: str) -> List[WiFiNetwork]:
        """Parse raw iw scan output."""
        networks = []
        cells = re.split(r"Cell\s+\d+\s+-\s+Address:", output)
        for cell in cells[1:]:
            try:
                bssid_match = re.search(r"([0-9A-F:]{17})", cell)
                if not bssid_match:
                    continue
                bssid = bssid_match.group(1)

                ssid_match = re.search(r"SSID:\s+(.+)", cell)
                ssid = ssid_match.group(1).strip() if ssid_match else "Unknown"

                signal_match = re.search(r"signal:\s+(-?\d+\.?\d*)", cell)
                signal = int(float(signal_match.group(1))) if signal_match else -50

                freq_match = re.search(r"DS Parameter set: channel\s+(\d+)", cell)
                channel = int(freq_match.group(1)) if freq_match else 1

                freq_match = re.search(r"frequency:\s+(\d+)", cell)
                frequency = float(freq_match.group(1)) if freq_match else 2437.0

                # Detect encryption
                if "Privacy" in cell:
                    if "WPA3" in cell:
                        encryption = "WPA3"
                        cipher = "CCMP"
                    elif "WPA2" in cell:
                        encryption = "WPA2"
                        cipher = "CCMP"
                    elif "WEP" in cell:
                        encryption = "WEP"
                        cipher = "WEP"
                    else:
                        encryption = "WPA"
                        cipher = "TKIP"
                else:
                    encryption = "OPEN"
                    cipher = "NONE"

                networks.append(WiFiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    signal=signal,
                    frequency=frequency,
                    encryption=encryption,
                    cipher=cipher,
                    channel=channel,
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ))
            except (ValueError, AttributeError) as e:
                logger.warning(f"Failed to parse cell: {e}")
                continue

        return networks

    def scan_simulated(self) -> List[WiFiNetwork]:
        """Return simulated WiFi networks for testing."""
        import copy
        networks = copy.deepcopy(SIMULATED_NETWORKS)
        for net in networks:
            net.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logger.info("Using simulated WiFi networks")
        return networks

    def scan(self) -> List[WiFiNetwork]:
        """Run a WiFi scan, using real scan or simulated data as fallback."""
        if not self.use_simulated:
            networks = self.scan_real()
            if networks:
                return networks
            logger.warning("Real scan returned no results; falling back to simulated data")

        return self.scan_simulated()
