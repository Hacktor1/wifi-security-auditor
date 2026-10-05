# WiFi Security Auditor

Core modules for WiFi network scanning, security analysis, and reporting.

## Usage

```bash
# Simulated mode (no WiFi hardware required)
python -m wifi_auditor --simulated

# Real WiFi scan
sudo python -m wifi_auditor --interface wlan0
```

## Configuration

Edit `config.yaml` to customize:

```yaml
scanner:
  interface: "wlan0"      # WiFi interface
  timeout: 5              # Scan timeout in seconds
  use_simulated: true     # Fallback to simulated data

thresholds:
  signal_strength: -70    # dBm - networks below this are flagged

report:
  output_dir: "reports"   # Where to save HTML reports
  format: "html"
```
