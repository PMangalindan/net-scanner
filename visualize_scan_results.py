"""Generate an HTML dashboard from network scan JSON results.

Usage:
  python visualize_scan_results.py --input scan_results.json
  python visualize_scan_results.py --input scan_results.json --output dashboard.html --open
"""

from __future__ import annotations

import argparse
import json
import statistics
import webbrowser
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render scan results JSON into a visual HTML dashboard."
    )
    parser.add_argument(
        "--input",
        default="scan_results.json",
        help="Path to scan results JSON file (default: scan_results.json)",
    )
    parser.add_argument(
        "--output",
        default="scan_results_dashboard.html",
        help="Path to output HTML file (default: scan_results_dashboard.html)",
    )
    parser.add_argument(
        "--open",
        action="store_true",
        help="Open the generated dashboard in your default browser.",
    )
    return parser.parse_args()


def safe_html(text: Any) -> str:
    raw = "" if text is None else str(text)
    return (
        raw.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def load_results(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    content = path.read_text(encoding="utf-8").strip()
    if not content:
        return []

    data = json.loads(content)
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = [data]
    else:
        raise ValueError("Expected JSON array or object.")

    normalized: list[dict[str, Any]] = []
    for item in rows:
        if isinstance(item, dict):
            normalized.append(item)
    return normalized


def top_n(counter: Counter[str], n: int = 8) -> list[tuple[str, int]]:
    return counter.most_common(n)


def normalize_name(value: Any, default: str = "unknown") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def build_bar_rows(items: list[tuple[str, int]], max_width: int = 320) -> str:
    if not items:
        return '<p class="muted">No data.</p>'

    peak = max(count for _, count in items)
    rows: list[str] = []
    for label, count in items:
        pct = 0 if peak == 0 else int((count / peak) * 100)
        width = 0 if peak == 0 else int((count / peak) * max_width)
        rows.append(
            "".join(
                [
                    '<div class="bar-row">',
                    f'<div class="bar-label" title="{safe_html(label)}">{safe_html(label)}</div>',
                    '<div class="bar-track">',
                    f'<div class="bar-fill" style="width: {width}px"></div>',
                    "</div>",
                    f'<div class="bar-meta">{count} ({pct}%)</div>',
                    "</div>",
                ]
            )
        )
    return "\n".join(rows)


def compute_stats(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    online = sum(1 for row in results if bool(row.get("online")))
    offline = total - online

    latencies: list[float] = []
    all_ports: Counter[str] = Counter()
    os_hints: Counter[str] = Counter()
    web_hosts = 0
    snmp_hosts = 0

    for row in results:
        latency = row.get("latency_ms")
        if isinstance(latency, (int, float)):
            latencies.append(float(latency))

        open_ports = row.get("open_ports")
        if isinstance(open_ports, list):
            for port in open_ports:
                all_ports.update([normalize_name(port)])

        hints = row.get("device_hints")
        if isinstance(hints, list):
            for hint in hints:
                hint_text = normalize_name(hint)
                if "linux" in hint_text.lower():
                    os_hints.update(["Linux/Unix"])
                elif "windows" in hint_text.lower():
                    os_hints.update(["Windows"])

        if row.get("http_status") is not None or row.get("http_title"):
            web_hosts += 1

        if bool(row.get("snmp_enabled")):
            snmp_hosts += 1

    avg_latency = round(statistics.mean(latencies), 2) if latencies else None
    max_latency = round(max(latencies), 2) if latencies else None

    return {
        "total": total,
        "online": online,
        "offline": offline,
        "online_pct": round((online / total) * 100, 1) if total else 0,
        "avg_latency": avg_latency,
        "max_latency": max_latency,
        "web_hosts": web_hosts,
        "snmp_hosts": snmp_hosts,
        "top_ports": top_n(all_ports),
        "os_hints": top_n(os_hints, n=5),
    }


def render_table(results: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for row in sorted(results, key=lambda x: str(x.get("ip", ""))):
        ip = safe_html(row.get("ip", "-"))
        status = "Online" if row.get("online") else "Offline"
        status_class = "up" if row.get("online") else "down"
        hostname = safe_html(row.get("hostname", "-"))
        ttl = safe_html(row.get("ttl", "-"))
        latency = safe_html(row.get("latency_ms", "-"))
        ports = row.get("open_ports")
        port_text = ", ".join(str(p) for p in ports) if isinstance(ports, list) and ports else "-"
        hints = row.get("device_hints")
        hint_text = "; ".join(str(h) for h in hints) if isinstance(hints, list) and hints else "-"

        rows.append(
            "".join(
                [
                    "<tr>",
                    f"<td>{ip}</td>",
                    f'<td><span class="pill {status_class}">{status}</span></td>',
                    f"<td>{hostname}</td>",
                    f"<td>{ttl}</td>",
                    f"<td>{latency}</td>",
                    f"<td>{safe_html(port_text)}</td>",
                    f"<td>{safe_html(hint_text)}</td>",
                    "</tr>",
                ]
            )
        )

    if not rows:
        rows.append('<tr><td colspan="7" class="muted">No scan records found.</td></tr>')

    return "\n".join(rows)


def render_html(results: list[dict[str, Any]], source_file: Path) -> str:
    stats = compute_stats(results)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    top_ports_html = build_bar_rows(stats["top_ports"])
    os_hints_html = build_bar_rows(stats["os_hints"])
    table_html = render_table(results)

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Network Scan Dashboard</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --ink: #141a2a;
      --muted: #5f6a88;
      --brand: #0f7b6c;
      --brand-soft: #dff4f1;
      --warn: #f4b400;
      --danger: #d93025;
      --ring: #d7deef;
      --shadow: 0 10px 28px rgba(20, 26, 42, 0.08);
    }}

    * {{ box-sizing: border-box; }}

    body {{
      margin: 0;
      font-family: "Segoe UI", "Trebuchet MS", Verdana, sans-serif;
      color: var(--ink);
      background:
        radial-gradient(1200px 500px at -10% -20%, #d7ecff 0%, transparent 60%),
        radial-gradient(1000px 450px at 110% -10%, #d7f7ef 0%, transparent 60%),
        var(--bg);
    }}

    .container {{
      max-width: 1200px;
      margin: 32px auto;
      padding: 0 16px 28px;
    }}

    .header {{
      background: linear-gradient(130deg, #0f7b6c, #1269a8);
      color: #fff;
      border-radius: 18px;
      padding: 20px;
      box-shadow: var(--shadow);
      margin-bottom: 16px;
    }}

    .header h1 {{
      margin: 0 0 8px;
      font-size: 1.6rem;
      letter-spacing: 0.3px;
    }}

    .header p {{
      margin: 4px 0;
      color: rgba(255, 255, 255, 0.9);
      font-size: 0.95rem;
    }}

    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
      margin: 16px 0;
    }}

    .card {{
      background: var(--panel);
      border: 1px solid var(--ring);
      border-radius: 14px;
      box-shadow: var(--shadow);
      padding: 14px;
    }}

    .card .label {{
      color: var(--muted);
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}

    .card .value {{
      margin-top: 8px;
      font-size: 1.6rem;
      font-weight: 700;
    }}

    .split {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-bottom: 12px;
    }}

    .panel {{
      background: var(--panel);
      border: 1px solid var(--ring);
      border-radius: 14px;
      box-shadow: var(--shadow);
      padding: 14px;
      overflow: hidden;
    }}

    .panel h2 {{
      margin: 0 0 12px;
      font-size: 1.04rem;
    }}

    .bar-row {{
      display: grid;
      grid-template-columns: minmax(120px, 220px) 1fr minmax(70px, 90px);
      align-items: center;
      gap: 10px;
      margin: 8px 0;
    }}

    .bar-label {{
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      font-size: 0.92rem;
    }}

    .bar-track {{
      background: #ebeff9;
      border-radius: 999px;
      height: 12px;
      position: relative;
      overflow: hidden;
    }}

    .bar-fill {{
      background: linear-gradient(90deg, #11846f, #17a4d6);
      height: 100%;
      border-radius: inherit;
    }}

    .bar-meta {{
      text-align: right;
      color: var(--muted);
      font-size: 0.86rem;
    }}

    .table-wrap {{
      overflow-x: auto;
      border-radius: 12px;
      border: 1px solid var(--ring);
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 860px;
      background: #fff;
    }}

    thead th {{
      text-align: left;
      font-size: 0.82rem;
      letter-spacing: 0.4px;
      text-transform: uppercase;
      color: var(--muted);
      background: #f1f5ff;
      border-bottom: 1px solid var(--ring);
      padding: 10px;
      position: sticky;
      top: 0;
      z-index: 1;
    }}

    tbody td {{
      border-bottom: 1px solid #eef2fb;
      padding: 10px;
      font-size: 0.9rem;
      vertical-align: top;
    }}

    tbody tr:hover {{
      background: #f7fbff;
    }}

    .pill {{
      display: inline-block;
      border-radius: 999px;
      padding: 2px 10px;
      font-size: 0.8rem;
      font-weight: 600;
    }}

    .pill.up {{
      color: #0a6f60;
      background: var(--brand-soft);
    }}

    .pill.down {{
      color: #9b1b14;
      background: #fee8e7;
    }}

    .muted {{
      color: var(--muted);
      font-style: italic;
    }}

    @media (max-width: 960px) {{
      .split {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <div class=\"container\">
    <div class=\"header\">
      <h1>Network Scan Dashboard</h1>
      <p>Source: {safe_html(source_file.name)}</p>
      <p>Generated: {safe_html(generated_at)}</p>
    </div>

    <div class=\"cards\">
      <div class=\"card\">
        <div class=\"label\">Hosts Scanned</div>
        <div class=\"value\">{stats['total']}</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Online Hosts</div>
        <div class=\"value\">{stats['online']}</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Offline Hosts</div>
        <div class=\"value\">{stats['offline']}</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Online Ratio</div>
        <div class=\"value\">{stats['online_pct']}%</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Avg Latency</div>
        <div class=\"value\">{stats['avg_latency'] if stats['avg_latency'] is not None else 'N/A'} ms</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Web Endpoints</div>
        <div class=\"value\">{stats['web_hosts']}</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">SNMP Enabled</div>
        <div class=\"value\">{stats['snmp_hosts']}</div>
      </div>
      <div class=\"card\">
        <div class=\"label\">Max Latency</div>
        <div class=\"value\">{stats['max_latency'] if stats['max_latency'] is not None else 'N/A'} ms</div>
      </div>
    </div>

    <div class=\"split\">
      <div class=\"panel\">
        <h2>Most Common Open Ports</h2>
        {top_ports_html}
      </div>
      <div class=\"panel\">
        <h2>OS Hints (from device_hints)</h2>
        {os_hints_html}
      </div>
    </div>

    <div class=\"panel\">
      <h2>Host Details</h2>
      <div class=\"table-wrap\">
        <table>
          <thead>
            <tr>
              <th>IP</th>
              <th>Status</th>
              <th>Hostname</th>
              <th>TTL</th>
              <th>Latency (ms)</th>
              <th>Open Ports</th>
              <th>Device Hints</th>
            </tr>
          </thead>
          <tbody>
            {table_html}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>
"""


def main() -> int:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve()

    results = load_results(input_path)
    html = render_html(results, input_path)
    output_path.write_text(html, encoding="utf-8")

    print(f"Dashboard created: {output_path}")
    print(f"Records visualized: {len(results)}")

    if args.open:
        webbrowser.open(output_path.as_uri())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
