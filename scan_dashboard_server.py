"""Serve an interactive scan dashboard with a Run Scan action.

Usage:
  python scan_dashboard_server.py --input scan_results.json --open

This starts a local web server where you can trigger network_scan_poc.py
from the dashboard and immediately refresh the visuals.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote_plus, urlparse

from visualize_scan_results import load_results, render_html, safe_html


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a local dashboard server that can trigger network scans."
    )
    parser.add_argument(
        "--input",
        default="scan_results.json",
        help="Scan results JSON file used by the dashboard (default: scan_results.json)",
    )
    parser.add_argument(
        "--scanner",
        default="network_scan_poc.py",
        help="Scanner script path (default: network_scan_poc.py)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Server port (default: 8765)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open dashboard in browser after startup.",
    )
    parser.add_argument(
        "--default-cidr",
        default="192.168.1.0/24",
        help="Pre-filled CIDR value in the scan form.",
    )
    parser.add_argument(
        "--default-workers",
        type=int,
        default=32,
        help="Pre-filled workers value in the scan form.",
    )
    parser.add_argument(
        "--default-timeout",
        type=float,
        default=1.0,
        help="Pre-filled ping timeout value in the scan form.",
    )
    parser.add_argument(
        "--default-ports",
        default="22,23,53,80,443,445,3389,9100",
        help="Pre-filled comma-separated ports in the scan form.",
    )
    parser.add_argument(
        "--default-port-timeout",
        type=float,
        default=0.5,
        help="Pre-filled TCP connect timeout value in the scan form.",
    )
    parser.add_argument(
        "--default-snmp-community",
        default="public",
        help="Pre-filled SNMP community value in the scan form.",
    )
    return parser.parse_args()


def parse_positive_int(value: str, field_name: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise ValueError(f"{field_name} must be >= 1")
    return parsed


def parse_positive_float(value: str, field_name: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise ValueError(f"{field_name} must be > 0")
    return parsed


def validate_ports(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError("ports cannot be empty")
    if not re.fullmatch(r"\d{1,5}(\s*,\s*\d{1,5})*", text):
        raise ValueError("ports must be comma-separated integers")

    ports = [int(item.strip()) for item in text.split(",") if item.strip()]
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")

    return ",".join(str(port) for port in ports)


def count_scanned_hosts(output_text: str) -> str:
    match = re.search(r"Scanned:\s*(\d+)", output_text)
    if not match:
        return "unknown"
    return match.group(1)


def build_controls_html(defaults: dict[str, str], message: str, level: str) -> str:
    message_html = ""
    if message:
        state_class = "ok" if level == "success" else "err"
        message_html = f'<div class="scan-msg {state_class}">{safe_html(message)}</div>'

    return f"""
    <div class="panel control-panel">
      <h2>Run New Scan</h2>
      {message_html}
      <form method="post" action="/run-scan" class="scan-form">
        <label>CIDR
          <input type="text" name="cidr" value="{safe_html(defaults['cidr'])}" required />
        </label>
        <label>Workers
          <input type="number" name="workers" min="1" value="{safe_html(defaults['workers'])}" required />
        </label>
        <label>Ping Timeout (s)
          <input type="number" name="timeout" min="0.1" step="0.1" value="{safe_html(defaults['timeout'])}" required />
        </label>
        <label>Port Timeout (s)
          <input type="number" name="port_timeout" min="0.1" step="0.1" value="{safe_html(defaults['port_timeout'])}" required />
        </label>
        <label>Ports
          <input type="text" name="ports" value="{safe_html(defaults['ports'])}" required />
        </label>
        <label>SNMP Community
          <input type="text" name="snmp_community" value="{safe_html(defaults['snmp_community'])}" />
        </label>

        <label class="checkbox"><input type="checkbox" name="snmp" /> Enable SNMP polling</label>
        <label class="checkbox"><input type="checkbox" name="online_only" /> Save online hosts only</label>

        <button type="submit">Run Scan And Refresh Dashboard</button>
      </form>
    </div>
    <style>
      .control-panel {{ margin-bottom: 12px; }}
      .scan-form {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 10px;
        align-items: end;
      }}
      .scan-form label {{
        display: flex;
        flex-direction: column;
        font-size: 0.88rem;
        color: #304062;
        gap: 6px;
      }}
      .scan-form input[type="text"],
      .scan-form input[type="number"] {{
        border: 1px solid #cad5ef;
        border-radius: 9px;
        padding: 8px 10px;
        font-size: 0.92rem;
        background: #fff;
      }}
      .scan-form .checkbox {{
        flex-direction: row;
        align-items: center;
        gap: 8px;
      }}
      .scan-form button {{
        border: none;
        border-radius: 10px;
        padding: 10px 12px;
        color: #fff;
        font-weight: 600;
        cursor: pointer;
        background: linear-gradient(120deg, #0f7b6c, #1269a8);
      }}
      .scan-msg {{
        margin-bottom: 10px;
        padding: 10px 12px;
        border-radius: 10px;
        font-size: 0.9rem;
      }}
      .scan-msg.ok {{
        background: #e6f6f3;
        color: #0a6f60;
        border: 1px solid #b8e4dc;
      }}
      .scan-msg.err {{
        background: #feeceb;
        color: #9b1b14;
        border: 1px solid #f4c9c7;
      }}
    </style>
    """


def build_dashboard_page(
    results_path: Path,
    defaults: dict[str, str],
    message: str,
    level: str,
) -> str:
    try:
        results = load_results(results_path)
    except Exception:
        results = []

    base_html = render_html(results, results_path)
    control_html = build_controls_html(defaults, message, level)
    marker = '<div class="cards">'
    if marker in base_html:
        return base_html.replace(marker, control_html + "\n" + marker, 1)

    return control_html + base_html


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        query = parse_qs(parsed.query)
        message = query.get("message", [""])[0]
        level = query.get("level", ["info"])[0]

        page = build_dashboard_page(
            self.server.results_path,
            self.server.form_defaults,
            message,
            level,
        )
        body = page.encode("utf-8")

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if self.path != "/run-scan":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        form = parse_qs(payload)

        try:
            cidr = form.get("cidr", [""])[0].strip()
            if not cidr:
                raise ValueError("CIDR is required")

            workers = parse_positive_int(form.get("workers", [self.server.form_defaults["workers"]])[0], "workers")
            timeout = parse_positive_float(form.get("timeout", [self.server.form_defaults["timeout"]])[0], "timeout")
            port_timeout = parse_positive_float(
                form.get("port_timeout", [self.server.form_defaults["port_timeout"]])[0],
                "port-timeout",
            )
            ports = validate_ports(form.get("ports", [self.server.form_defaults["ports"]])[0])
            snmp = "snmp" in form
            online_only = "online_only" in form
            snmp_community = form.get("snmp_community", [self.server.form_defaults["snmp_community"]])[0].strip() or "public"

            command = [
                sys.executable,
                str(self.server.scanner_path),
                cidr,
                "--workers",
                str(workers),
                "--timeout",
                str(timeout),
                "--ports",
                ports,
                "--port-timeout",
                str(port_timeout),
                "--json-out",
                str(self.server.results_path),
            ]
            if snmp:
                command.extend(["--snmp", "--snmp-community", snmp_community])
            if online_only:
                command.append("--online-only")

            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            output_text = (completed.stdout or "") + "\n" + (completed.stderr or "")

            if completed.returncode == 0:
                scanned_hosts = count_scanned_hosts(output_text)
                message = f"Scan finished successfully. Scanned hosts: {scanned_hosts}."
                level = "success"
            else:
                condensed = " ".join(output_text.strip().splitlines()[-2:]).strip()
                message = f"Scan failed (exit {completed.returncode}). {condensed or 'Check terminal output.'}"
                level = "error"

        except Exception as exc:
            message = f"Scan request error: {exc}"
            level = "error"

        target = f"/?level={quote_plus(level)}&message={quote_plus(message)}"
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", target)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        return


class DashboardServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        results_path: Path,
        scanner_path: Path,
        form_defaults: dict[str, str],
    ) -> None:
        super().__init__(server_address, handler_class)
        self.results_path = results_path
        self.scanner_path = scanner_path
        self.form_defaults = form_defaults


def main() -> int:
    args = parse_args()

    results_path = Path(args.input).expanduser().resolve()
    scanner_path = Path(args.scanner).expanduser().resolve()

    if not scanner_path.exists():
        print(f"Scanner script not found: {scanner_path}", file=sys.stderr)
        return 1

    form_defaults = {
        "cidr": args.default_cidr,
        "workers": str(args.default_workers),
        "timeout": str(args.default_timeout),
        "port_timeout": str(args.default_port_timeout),
        "ports": args.default_ports,
        "snmp_community": args.default_snmp_community,
    }

    server = DashboardServer(
        (args.host, args.port),
        DashboardHandler,
        results_path,
        scanner_path,
        form_defaults,
    )

    url = f"http://{args.host}:{args.port}/"
    print(f"Dashboard server running at {url}")

    if args.open:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard server...")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
