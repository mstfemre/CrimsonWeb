"""Report helpers for CrimsonWeb."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

from .audit import LOG_FILE_JSONL, LOG_FILE_TEXT
from .models import ServiceResult, Target


def trim_text(value: str | None, width: int) -> str:
    text = value or ""
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev.upper(), 4)


def web_finding_count(result: ServiceResult) -> int:
    return (
        len(result.sensitive_paths)
        + len(result.api_paths)
        + len(result.security_headers)
        + len(result.cookie_findings)
        + len(result.cors_findings)
    )


def max_severity(results: dict[int, ServiceResult]) -> str:
    severities = []
    for result in results.values():
        for cve in result.cves:
            severities.append(cve.get("severity", "unknown"))
        for finding in result.cors_findings + result.security_headers + result.cookie_findings:
            severities.append(str(finding.get("severity", "LOW")))
    if not severities:
        return "LOW" if any(web_finding_count(r) for r in results.values()) else "INFO"
    severities.sort(key=_severity_rank)
    return severities[0].upper()


def write_executive_report(
    target: Target,
    results: dict[int, ServiceResult],
    engagement_id: str | None,
    scan_mode: str,
    web_policy: dict,
    raw_report_path: Path,
    output_path: Path,
    tool_name: str = "CrimsonWeb",
    tool_version: str = "unknown",
) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    total_cves = sum(len(r.cves) for r in results.values())
    total_sensitive = sum(len(r.sensitive_paths) for r in results.values())
    total_api = sum(len(r.api_paths) for r in results.values())
    total_web_findings = sum(web_finding_count(r) for r in results.values())
    open_count = len(results)
    max_sev = max_severity(results)
    risk_label = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Informational",
    }.get(max_sev, "Unknown")
    lines: list[str] = []
    lines.append(f"# CrimsonWeb Scan Report - {target.original}")
    lines.append("")
    lines.append(f"- **Scan time (UTC):** {timestamp}")
    lines.append(f"- **Target:** `{target.original}` (`{target.address}`)")
    lines.append(f"- **Engagement ID:** `{engagement_id or 'N/A'}`")
    lines.append(f"- **Scan mode:** {scan_mode}")
    lines.append(f"- **Egress mode:** {web_policy.get('egress', {}).get('mode', 'direct')}")
    lines.append(f"- **Tool:** {tool_name} v{tool_version}")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"Scan identified **{open_count}** open service(s), "
        f"**{total_cves}** potential CVE match(es), "
        f"**{total_sensitive}** sensitive path exposure(s), "
        f"**{total_api}** API endpoint indicator(s), "
        f"**{total_web_findings}** total web hardening finding(s). "
        f"Overall risk: **{risk_label}**."
    )
    lines.append("")
    if max_sev in {"CRITICAL", "HIGH"}:
        lines.append("**Recommendation:** Immediate remediation required for findings flagged Critical/High. ")
        lines.append("See Findings section. Patch within 72 hours.")
    elif max_sev == "MEDIUM":
        lines.append("**Recommendation:** Address findings within the next planned patch cycle.")
    else:
        lines.append("**Recommendation:** Monitor and address as part of normal hardening.")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append("Authorized/lab scan executed against the intended in-scope hosts. ")
    lines.append("Techniques applied:")
    lines.append("")
    lines.append("- Port discovery (async-connect / SYN as configured)")
    lines.append("- Service fingerprinting via banner grabbing and protocol probes")
    lines.append("- Passive WAF/header analysis")
    lines.append("- HTTP security header, cookie flag, CORS and API path checks")
    lines.append("- TLS certificate metadata collection when safe for the configured egress")
    lines.append("- Sensitive path enumeration (limited list)")
    lines.append("- NVD CVE correlation by detected version")
    lines.append("- Multi-egress traffic with ban-aware backoff and adaptive pacing")
    lines.append("")
    lines.append("Excluded by design: active exploitation, DoS, exfiltration, social engineering.")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not any(r.cves or web_finding_count(r) for r in results.values()):
        lines.append("_No CVE matches or web hardening findings identified._")
        lines.append("")
    else:
        for port in sorted(results):
            result = results[port]
            if not (result.cves or web_finding_count(result)):
                continue
            lines.append(f"### Port {port}/{result.transport} - {result.service}")
            lines.append("")
            lines.append(f"- **Version:** `{result.version}`")
            if result.title:
                lines.append(f"- **Title:** {trim_text(result.title, 80)}")
            if result.waf:
                lines.append(f"- **WAF detected:** {result.waf}")
            if result.sensitive_paths:
                lines.append("- **Sensitive paths exposed:**")
                for finding in result.sensitive_paths:
                    lines.append(f"    - `{finding.path}` (status={finding.status}, size={finding.size})")
            if result.api_paths:
                lines.append("- **API endpoint indicators:**")
                for finding in result.api_paths:
                    lines.append(f"    - `{finding.path}` (status={finding.status}, size={finding.size})")
            if result.security_headers:
                lines.append("- **Security header findings:**")
                for finding in result.security_headers:
                    lines.append(f"    - `{finding.get('name')}`: {finding.get('detail')}")
            if result.cookie_findings:
                lines.append("- **Cookie flag findings:**")
                for finding in result.cookie_findings:
                    lines.append(
                        f"    - `{finding.get('name')}`: {', '.join(finding.get('issues', []))}"
                    )
            if result.cors_findings:
                lines.append("- **CORS findings:**")
                for finding in result.cors_findings:
                    lines.append(
                        f"    - {finding.get('severity')}: {finding.get('detail')} "
                        f"(ACAO={finding.get('allow_origin')})"
                    )
            if result.tls_certificate:
                cert = result.tls_certificate
                lines.append("- **TLS certificate:**")
                lines.append(
                    f"    - subject={cert.get('subject_cn') or '-'}, "
                    f"issuer={cert.get('issuer_cn') or '-'}, "
                    f"expires={cert.get('not_after') or '-'}"
                )
            if result.mitre_attack:
                lines.append("- **MITRE ATT&CK mapping:**")
                for mapping in result.mitre_attack:
                    lines.append(
                        f"    - `{mapping.get('id')}` {mapping.get('technique')}: "
                        f"{mapping.get('reason')}"
                    )
            if result.cves:
                lines.append("- **Potential CVEs:**")
                for cve in result.cves:
                    lines.append(
                        f"    - `{cve.get('id')}` ({cve.get('severity', 'unknown')}): "
                        f"{trim_text(cve.get('description', ''), 200)}"
                    )
            lines.append("")
            lines.append("**Remediation:** Upgrade to a patched release, restrict exposure where possible, ")
            lines.append("monitor logs for exploitation attempts. Verify with vendor advisories.")
            lines.append("")
    lines.append("## MITRE ATT&CK Summary")
    lines.append("")
    unique_mitre: OrderedDict[str, dict[str, str]] = OrderedDict()
    for result in results.values():
        for mapping in result.mitre_attack:
            unique_mitre.setdefault(mapping.get("id", "unknown"), mapping)
    if not unique_mitre:
        lines.append("_No ATT&CK mappings generated._")
    else:
        for mapping in unique_mitre.values():
            lines.append(
                f"- `{mapping.get('id')}` **{mapping.get('technique')}**: {mapping.get('reason')}"
            )
    lines.append("")
    lines.append("## Egress & Behavioral Log Summary")
    lines.append("")
    egress = web_policy.get("egress", {})
    nodes = egress.get("nodes", [])
    lines.append(f"- **Egress mode:** {egress.get('mode')}")
    lines.append(f"- **Total egress nodes:** {len(nodes)}")
    total_reqs = sum(n.get("total_requests", 0) for n in nodes)
    total_fails = sum(n.get("total_failures", 0) for n in nodes)
    lines.append(f"- **Total requests:** {total_reqs} (failures: {total_fails})")
    blocked = web_policy.get("blocked_targets", [])
    lines.append(f"- **Block events:** {len(blocked)}")
    if blocked:
        for ev in blocked[:10]:
            lines.append(f"    - `{ev.get('url')}` - {ev.get('reason')} (egress={ev.get('egress_id')})")
    lines.append("")
    lines.append("## Appendix")
    lines.append("")
    lines.append(f"- **Raw JSON report:** `{raw_report_path}`")
    lines.append(f"- **Audit log (text):** `{LOG_FILE_TEXT}`")
    lines.append(f"- **Audit log (JSONL):** `{LOG_FILE_JSONL}`")
    lines.append("")
    output_path.write_text("\n".join(lines), encoding="utf-8")
    return output_path
