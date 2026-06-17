# Network Scanner + Dashboard

Lightweight network discovery project with:
- A Python scanner for CIDR ranges
- A static HTML dashboard generator
- An interactive local dashboard that can run scans from the browser

## Files

- `network_scan_poc.py`: main scanner script
- `visualize_scan_results.py`: generates dashboard HTML from JSON results
- `scan_dashboard_server.py`: local web server with "Run Scan" form and live refresh
- `scan_results.json`: latest scan output (example)
- `scan_results_dashboard.html`: generated static dashboard (example)

## Requirements

- Windows PowerShell
- Python 3.10+
- Virtual environment in `myenv`
- `pysnmp` installed only if you want SNMP features

## Activate Environment (PowerShell)

```powershell
(Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& .\myenv\Scripts\Activate.ps1)
```

## Run a Scan (CLI)

Basic scan:

```powershell
python .\network_scan_poc.py 192.168.132.0/24 --json-out .\scan_results.json
```

Example with extra options:

```powershell
python .\network_scan_poc.py 192.168.132.0/24 --workers 32 --timeout 1 --ports 22,23,53,80,443,445,3389,9100 --port-timeout 0.5 --json-out .\scan_results.json
```

SNMP example:

```powershell
python .\network_scan_poc.py 192.168.132.0/24 --snmp --snmp-community public --json-out .\scan_results_snmp.json
```

## Generate Static Dashboard

```powershell
python .\visualize_scan_results.py --input .\scan_results.json --output .\scan_results_dashboard.html
```

Open automatically:

```powershell
python .\visualize_scan_results.py --input .\scan_results.json --output .\scan_results_dashboard.html --open
```

## Run Interactive Dashboard (Run Scan from UI)

```powershell
python .\scan_dashboard_server.py --input .\scan_results.json --open
```

Default URL:

- `http://127.0.0.1:8765/`

What you can do in the interactive dashboard:
- Enter CIDR and scan settings
- Click **Run Scan And Refresh Dashboard**
- View updated cards/charts/table immediately

## Common Options

Scanner (`network_scan_poc.py`) supports:
- positional `cidr`
- `--workers`
- `--timeout`
- `--ports`
- `--port-timeout`
- `--json-out`
- `--snmp`
- `--snmp-community`
- `--snmp-timeout`
- `--online-only`

Interactive dashboard server (`scan_dashboard_server.py`) supports:
- `--input`
- `--scanner`
- `--host`
- `--port`
- `--open`
- `--default-cidr`
- `--default-workers`
- `--default-timeout`
- `--default-ports`
- `--default-port-timeout`
- `--default-snmp-community`

## Typical Workflow

1. Activate environment.
2. Run scanner and write JSON.
3. Open interactive dashboard for repeated scans, or generate static dashboard for sharing.

## Troubleshooting

If SNMP mode fails with import/API errors:
- Verify environment activation.
- Check `pysnmp` installation in `myenv`.
- Ensure scanner and environment use the same Python interpreter.

If browser cannot connect to interactive dashboard:
- Confirm server is running.
- Check that port `8765` is available, or start with `--port 8788`.
