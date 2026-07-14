# Network Scanner + Dashboard

Lightweight network discovery proof of concept with three parts:
1. CLI scanner for one CIDR range
2. Static HTML dashboard generator
3. Local interactive dashboard that can trigger new scans

## Project Files

- network_scan_poc.py: main scanner (ping + service fingerprinting + optional SNMP)
- visualize_scan_results.py: renders a JSON results file into an HTML dashboard
- scan_dashboard_server.py: serves dashboard UI and runs scans from the browser
- requirements.txt: optional SNMP dependencies
- scan_results.json: example JSON output
- scan_results_dashboard.html: example rendered dashboard

## Requirements

- Python 3.10+
- PowerShell on Windows
- Network reachability to target CIDR

Notes:
- Scanner refuses very large ranges and currently caps scan size to 256 addresses.
- SNMP is optional. It is only used when --snmp is passed.

## Setup

Create and activate a virtual environment (if needed):

```powershell
python -m venv myenv
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& .\myenv\Scripts\Activate.ps1)
```

Install dependencies:

```powershell
pip install -r .\requirements.txt
```

If you do not use SNMP mode, the scanner can run without extra packages.

## Quick Start

Run a scan and save JSON:

```powershell
python .\network_scan_poc.py 192.168.1.0/24 --json-out .\scan_results.json
```

Generate dashboard HTML:

```powershell
python .\visualize_scan_results.py --input .\scan_results.json --output .\scan_results_dashboard.html --open
```

Run interactive dashboard server:

```powershell
python .\scan_dashboard_server.py --input .\scan_results.json --open
```

Default dashboard URL:

- http://127.0.0.1:8765/

## Scanner Usage

Basic:

```powershell
python .\network_scan_poc.py 192.168.1.0/24 --json-out .\scan_results.json
```

With custom speed and ports:

```powershell
python .\network_scan_poc.py 192.168.1.0/24 --workers 32 --timeout 1 --ports 22,23,53,80,443,445,3389,9100 --port-timeout 0.5 --json-out .\scan_results.json
```

With SNMP polling:

```powershell
python .\network_scan_poc.py 192.168.1.0/24 --snmp --snmp-community public --snmp-timeout 1 --json-out .\scan_results_snmp.json
```

Show only online hosts in terminal output and JSON:

```powershell
python .\network_scan_poc.py 192.168.1.0/24 --online-only --json-out .\scan_results_online.json
```

### Scanner Arguments

- cidr (required): target CIDR range
- --workers: max worker threads (default 32)
- --timeout: ping timeout seconds (default 1)
- --ports: comma-separated TCP ports to probe
- --port-timeout: TCP connect timeout seconds (default 0.5)
- --json-out: write results to JSON file
- --snmp: enable SNMP polling on UDP/161
- --snmp-community: SNMP v2c community (default public)
- --snmp-timeout: SNMP timeout seconds (default 1)
- --show-offline: include offline hosts (default behavior)
- --online-only: keep only online hosts in output

## Dashboard Options

### Static Dashboard

```powershell
python .\visualize_scan_results.py --input .\scan_results.json --output .\scan_results_dashboard.html
```

- --input: source JSON path
- --output: target HTML path
- --open: open in browser after render

### Interactive Dashboard Server

```powershell
python .\scan_dashboard_server.py --input .\scan_results.json --host 127.0.0.1 --port 8765 --open
```

Key arguments:

- --input: results JSON file used by the dashboard
- --scanner: scanner script path (default network_scan_poc.py)
- --host: server bind host (default 127.0.0.1)
- --port: server port (default 8765)
- --open: open browser on startup
- --log-file: optional rotating log file path
- --debug: enable debug logging
- --state-file: file used to remember last successful CIDR
- --default-cidr / --default-workers / --default-timeout / --default-ports / --default-port-timeout / --default-snmp-community: pre-filled form defaults

## Output Data

Each host record can include:

- ip, online, status
- latency_ms, ttl, hostname, mac_address
- open_ports
- http_title, http_server, http_status
- ssh_banner
- snmp_enabled and SNMP system fields
- device_hints
- checked_at

## Typical Workflow

1. Activate virtual environment.
2. Run scanner to produce or refresh JSON.
3. Choose a dashboard mode:
	- Static HTML for sharing snapshots.
	- Interactive server for repeated scans from browser UI.

## Troubleshooting

SNMP problems:

- Confirm virtual environment is activated.
- Reinstall dependencies with pip install -r requirements.txt.
- Ensure scanner is executed with the same Python environment where pysnmp is installed.

Dashboard not reachable:

- Confirm server process is running.
- Try another port, for example --port 8788.
- Check local firewall or endpoint security rules.

CIDR rejected:

- Use a smaller range (scanner enforces a 256-address cap).

No hosts detected:

- Verify CIDR and routing.
- Run with increased timeout values on slower networks.
