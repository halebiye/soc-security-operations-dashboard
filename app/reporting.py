"""Portable exports. HTML is autoescaped; Markdown never embeds raw HTML."""

import html
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES = Path(__file__).parent / "templates"
environment = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))


def markdown_text(value) -> str:
    value = html.escape(str(value), quote=True)
    for character in ("\\", "`", "*", "_", "[", "]", "|", "#", ">"):
        value = value.replace(character, "\\" + character)
    return value.replace("\r", " ").replace("\n", "<br>")


def render_report(data: dict, output_format: str) -> tuple[str, str]:
    if output_format == "json":
        return json.dumps(data, indent=2, ensure_ascii=False), "application/json"
    if output_format == "html":
        return environment.get_template("report.html").render(report=data), "text/html"
    if output_format != "markdown":
        raise ValueError("Unknown report format")
    lines = [
        "# SOC Security Operations Dashboard — Investigation Report",
        "",
        f"Generated: {data['generated_at']}",
        "",
        "**Synthetic data only. Detection matches require analyst validation.**",
        "",
        data["scope"],
        "",
        f"Filters: {markdown_text(json.dumps(data['filters'], ensure_ascii=False))}",
        "",
        f"Matching alerts: **{data['alert_count']}**",
        "",
        f"Dataset: {data['dataset_summary']['total_events']} events; {data['dataset_summary']['failed_logins']} failures.",
        "",
        f"Current configuration SHA-256: {data['config_hash']}",
        "",
    ]
    for alert in data["alerts"]:
        lines.extend(
            [
                f"## {alert['display_id']} · {markdown_text(alert['rule_name'])}",
                "",
                f"**{alert['severity'].upper()}** · {alert['status']} · {alert['last_seen']}",
                "",
                f"Rule: {alert['rule_id']} / v{markdown_text(alert['rule_version'])}",
                "",
                (
                    "MITRE ATT&CK: "
                    + (
                        ", ".join(
                            f"{markdown_text(item['id'])} {markdown_text(item['name'])} ({markdown_text(item['mapping'])})"
                            for item in alert.get("mitre_attack", [])
                        )
                        if alert.get("mitre_attack")
                        else "No direct mapping"
                    )
                ),
                "",
                "ATT&CK context: " + markdown_text(alert.get("mitre_attack_note", "")),
                "",
                f"Source: {markdown_text(alert['source_ip'])} · Account: {markdown_text(alert['username'])} · Host: {markdown_text(alert['hostname'])} · Service: {markdown_text(alert['service'])}",
                "",
                markdown_text(alert["explanation"]),
                "",
                "**Recommendation:** " + markdown_text(alert["recommendation"]),
                "",
                f"Rule snapshot SHA-256: {alert['config_hash']}",
                "",
                "| Event | Timestamp (UTC) | Source | Account | Host | Service | Outcome |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for event in alert["evidence"]:
            values = [
                event[key]
                for key in (
                    "event_id",
                    "timestamp",
                    "source_ip",
                    "username",
                    "hostname",
                    "service",
                    "event_type",
                )
            ]
            lines.append("| " + " | ".join(markdown_text(value) for value in values) + " |")
        lines.extend(["", "### Analyst activity", ""])
        for activity in alert["activity"]:
            lines.append(
                f"- {activity['timestamp']} · {markdown_text(activity['analyst'])} · {markdown_text(activity['content'])}"
            )
        lines.append("")
    return "\n".join(lines), "text/markdown"
