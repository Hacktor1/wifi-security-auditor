#!/usr/bin/env python3
"""
WiFi Security Auditor - Main Entry Point.

Usage:
    python -m wifi_auditor [--interface wlan0] [--simulated] [--output reports/]

Scans WiFi networks, analyzes security, and generates HTML audit reports.
"""

import argparse
import logging
import sys
import yaml
import os
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("wifi_auditor")


def load_config(config_path: str = None) -> dict:
    """Load configuration from YAML file."""
    default_config = {
        "scanner": {"interface": "wlan0", "timeout": 5, "use_simulated": True},
        "report": {"output_dir": "reports", "format": "html"},
        "thresholds": {"signal_strength": -70},
    }

    if config_path and os.path.isfile(config_path):
        try:
            with open(config_path, "r") as f:
                user_config = yaml.safe_load(f)
            if user_config:
                # Merge with defaults
                for key in default_config:
                    if key in user_config:
                        if isinstance(default_config[key], dict) and isinstance(user_config[key], dict):
                            default_config[key].update(user_config[key])
                        else:
                            default_config[key] = user_config[key]
            logger.info(f"Loaded config from {config_path}")
        except yaml.YAMLError as e:
            logger.warning(f"Failed to parse config YAML: {e}; using defaults")
        except Exception as e:
            logger.warning(f"Failed to load config: {e}; using defaults")
    else:
        logger.info("Using default configuration")

    return default_config


def main():
    """Main entry point for the WiFi Security Auditor."""
    parser = argparse.ArgumentParser(
        description="WiFi Security Auditor - scan and analyze WiFi network security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Auto-detect best mode
  %(prog)s --simulated              # Use simulated data
  %(prog)s --interface wlan0        # Specify WiFi interface
  %(prog)s --output /tmp/reports    # Custom output directory
  %(prog)s -v                       # Verbose output
        """,
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="WiFi interface to use (default: wlan0 or auto-detect)"
    )
    parser.add_argument(
        "--simulated", "-s",
        action="store_true",
        help="Use simulated WiFi networks"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Output directory for reports (default: reports)"
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to config YAML file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load configuration
    config = load_config(args.config)

    # Override with CLI args
    use_simulated = args.simulated or config["scanner"].get("use_simulated", True)
    interface = args.interface or config["scanner"].get("interface", "wlan0")
    output_dir = args.output or config["report"].get("output_dir", "reports")
    signal_threshold = config["thresholds"].get("signal_strength", -70)

    logger.info("=" * 60)
    logger.info("WiFi Security Auditor v1.0.0")
    logger.info("=" * 60)
    logger.info(f"Interface: {interface}")
    logger.info(f"Simulated mode: {use_simulated}")
    logger.info(f"Signal threshold: {signal_threshold} dBm")
    logger.info(f"Output directory: {output_dir}")
    logger.info("")

    # Import modules (lazy import to avoid circular deps)
    from wifi_auditor.scanner import Scanner
    from wifi_auditor.analyzer import Analyzer
    from wifi_auditor.reporter import Reporter

    # Step 1: Scan WiFi networks
    logger.info("📡 Scanning for WiFi networks...")
    scanner = Scanner(interface=interface, use_simulated=use_simulated)
    networks = scanner.scan()

    if not networks:
        logger.error("❌ No networks found. Try using --simulated flag.")
        print("\nNo WiFi networks were detected. Run with --simulated to use test data.\n")
        sys.exit(1)

    logger.info(f"✅ Found {len(networks)} networks:")
    for net in networks:
        logger.info(f"   {net.ssid} ({net.bssid}) - {net.encryption} - {net.signal} dBm")

    print(f"\n📡 Scanned {len(networks)} WiFi networks.\n")

    # Step 2: Analyze security
    logger.info("🔍 Analyzing network security...")
    analyzer = Analyzer(signal_threshold=signal_threshold)
    results = analyzer.analyze(networks)

    # Print summary
    critical = sum(1 for r in results if r["risk_level"] == "CRITICAL")
    high = sum(1 for r in results if r["risk_level"] == "HIGH")
    medium = sum(1 for r in results if r["risk_level"] == "MEDIUM")
    low = sum(1 for r in results if r["risk_level"] == "LOW")
    safe = sum(1 for r in results if r["risk_level"] == "SAFE")

    print(f"🔍 Analysis complete:")
    print(f"   Critical: {critical}")
    print(f"   High:     {high}")
    print(f"   Medium:   {medium}")
    print(f"   Low:      {low}")
    print(f"   Safe:     {safe}")
    print()

    # Step 3: Generate report
    logger.info("📄 Generating audit report...")
    reporter = Reporter(output_dir=output_dir)
    report_path = reporter.generate(results)

    print(f"📄 Report generated: {report_path}")
    print(f"\n✅ WiFi Security Audit complete!\n")

    # Print detailed findings
    print("=" * 60)
    print("DETAILED FINDINGS")
    print("=" * 60)
    for result in results:
        net = result["network"]
        print(f"\n📶 {net['ssid']} ({net['encryption']} / {result['risk_level']})")
        print(f"   BSSID: {net['bssid']} | Signal: {net['signal']} dBm")
        if result["vulnerabilities"]:
            for vuln in result["vulnerabilities"]:
                print(f"   ⚠️  [{vuln['severity']}] {vuln['name']}")
        else:
            print(f"   ✅ No vulnerabilities detected")

    print("\n" + "=" * 60)
    print(f"📄 Full report: {os.path.abspath(report_path)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
