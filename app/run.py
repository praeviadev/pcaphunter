from __future__ import annotations

import argparse
import ipaddress
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, pstdev
from typing import Any


# =========================
# Config
# =========================

CONFIG: dict[str, Any] = {
    "dns_longest_label_min": 20,
    "dns_entropy_min": 3.8,
    "large_outbound_bytes_min": 500_000,
    "many_unique_externals_min": 10,
    "beacon_min_connections": 5,
    "beacon_min_avg_interval": 2.0,
    "beacon_max_jitter_ratio": 0.35,
    "small_download_repeat_min": 3,
    "small_download_max_bytes": 200_000,
    "print_max_findings": 200,
    "suspicious_tlds": (
        ".top",
        ".xyz",
        ".buzz",
        ".click",
        ".shop",
        ".lol",
        ".fit",
        ".country",
        ".stream",
    ),
    "known_bad_domains": {
        "bruvogex.top",
        "exxarzo.com",
    },
    "suspicious_uri_tokens": (
        "/health",
        "/update",
        "/verify",
        "/captcha",
        "/gate",
        "/check",
        "/js.php",
        "/cdn",
    ),
    "suspicious_script_extensions": (
        ".js",
        ".hta",
        ".ps1",
        ".vbs",
        ".cmd",
        ".bat",
    ),
}


# =========================
# Utilities
# =========================

def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def load_zeek_json_log(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return records


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalize_host(value: str) -> str:
    return value.strip().lower().rstrip(".")


def get_uid_map(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for rec in records:
        uid = rec.get("uid")
        if uid:
            out[uid] = rec
    return out


def get_host_pair(rec: dict[str, Any]) -> tuple[str, str]:
    return rec.get("id.orig_h", ""), rec.get("id.resp_h", "")


def finding(
    finding_type: str,
    severity: str,
    reason: str,
    **kwargs: Any,
) -> dict[str, Any]:
    item = {
        "type": finding_type,
        "severity": severity,
        "reason": reason,
    }
    item.update(kwargs)
    return item


# =========================
# Context / Baselines
# =========================

def summarize_logs(
    conn_logs: list[dict[str, Any]],
    dns_logs: list[dict[str, Any]],
    http_logs: list[dict[str, Any]],
    ssl_logs: list[dict[str, Any]],
    files_logs: list[dict[str, Any]],
) -> None:
    print(f"[INFO] Loaded conn.log records:  {len(conn_logs)}")
    print(f"[INFO] Loaded dns.log records:   {len(dns_logs)}")
    print(f"[INFO] Loaded http.log records:  {len(http_logs)}")
    print(f"[INFO] Loaded ssl.log records:   {len(ssl_logs)}")
    print(f"[INFO] Loaded files.log records: {len(files_logs)}")

    internal_hosts: set[str] = set()
    external_hosts: set[str] = set()

    for rec in conn_logs:
        src, dst = get_host_pair(rec)
        if src and is_private_ip(src):
            internal_hosts.add(src)
        if dst and not is_private_ip(dst):
            external_hosts.add(dst)

    print(f"[INFO] Internal hosts observed:   {len(internal_hosts)}")
    print(f"[INFO] External IPs observed:     {len(external_hosts)}")
    print()


def baseline_external_connections(conn_logs: list[dict[str, Any]], limit: int = 20) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    count = 0

    for rec in conn_logs:
        src, dst = get_host_pair(rec)
        if not src or not dst:
            continue
        if is_private_ip(src) and not is_private_ip(dst):
            findings.append(
                finding(
                    "external_connection_observed",
                    "info",
                    "Baseline visibility: internal host connected to an external destination.",
                    src_ip=src,
                    dst_ip=dst,
                    proto=rec.get("proto"),
                    service=rec.get("service"),
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                    orig_bytes=safe_int(rec.get("orig_bytes")),
                    resp_bytes=safe_int(rec.get("resp_bytes")),
                )
            )
            count += 1
            if count >= limit:
                break

    return findings


# =========================
# Generic Hunts
# =========================

def hunt_dns_anomalies(dns_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for rec in dns_logs:
        query = normalize_host(rec.get("query", ""))
        src = rec.get("id.orig_h", "")
        if not query or not src:
            continue

        labels = query.split(".")
        longest_label = max((len(label) for label in labels), default=0)
        entropy = shannon_entropy(query)

        if longest_label >= CONFIG["dns_longest_label_min"] or entropy >= CONFIG["dns_entropy_min"]:
            findings.append(
                finding(
                    "suspicious_dns",
                    "medium",
                    "High-entropy or unusually long DNS query may indicate DGA, tunneling, or encoded subdomains.",
                    src_ip=src,
                    query=query,
                    longest_label=longest_label,
                    entropy=round(entropy, 2),
                    answers=rec.get("answers"),
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    return findings


def hunt_suspicious_tlds(dns_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for rec in dns_logs:
        query = normalize_host(rec.get("query", ""))
        src = rec.get("id.orig_h", "")
        if not query:
            continue

        if query.endswith(CONFIG["suspicious_tlds"]):
            findings.append(
                finding(
                    "suspicious_tld",
                    "high",
                    "Suspicious TLD often seen in commodity delivery, staging, or lure infrastructure.",
                    src_ip=src,
                    query=query,
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    return findings


def hunt_large_outbound(conn_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for rec in conn_logs:
        src, dst = get_host_pair(rec)
        if not src or not dst:
            continue
        if not (is_private_ip(src) and not is_private_ip(dst)):
            continue

        orig_bytes = safe_int(rec.get("orig_bytes"))
        if orig_bytes >= CONFIG["large_outbound_bytes_min"]:
            findings.append(
                finding(
                    "large_outbound_transfer",
                    "high",
                    "Large outbound transfer from internal host to external destination.",
                    src_ip=src,
                    dst_ip=dst,
                    proto=rec.get("proto"),
                    service=rec.get("service"),
                    orig_bytes=orig_bytes,
                    resp_bytes=safe_int(rec.get("resp_bytes")),
                    duration=safe_float(rec.get("duration")),
                    conn_state=rec.get("conn_state"),
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    return findings


def hunt_many_unique_externals(conn_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    host_to_externals: defaultdict[str, set[str]] = defaultdict(set)

    for rec in conn_logs:
        src, dst = get_host_pair(rec)
        if not src or not dst:
            continue
        if is_private_ip(src) and not is_private_ip(dst):
            host_to_externals[src].add(dst)

    for host, dsts in host_to_externals.items():
        if len(dsts) >= CONFIG["many_unique_externals_min"]:
            findings.append(
                finding(
                    "many_unique_external_connections",
                    "medium",
                    "Internal host contacted an unusually large number of unique external IPs.",
                    src_ip=host,
                    unique_external_count=len(dsts),
                    sample_destinations=sorted(dsts)[:15],
                )
            )

    return findings


def hunt_beaconing(conn_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    grouped: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

    for rec in conn_logs:
        src, dst = get_host_pair(rec)
        if src and dst and is_private_ip(src) and not is_private_ip(dst):
            grouped[(src, dst)].append(rec)

    for (src, dst), recs in grouped.items():
        if len(recs) < CONFIG["beacon_min_connections"]:
            continue

        timestamps = sorted(safe_float(r.get("ts")) for r in recs if r.get("ts") is not None)
        if len(timestamps) < CONFIG["beacon_min_connections"]:
            continue

        deltas = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        if len(deltas) < 3:
            continue

        avg_delta = mean(deltas)
        std_delta = pstdev(deltas) if len(deltas) > 1 else 0.0
        max_jitter_ratio = CONFIG["beacon_max_jitter_ratio"]

        if avg_delta >= CONFIG["beacon_min_avg_interval"] and std_delta <= (avg_delta * max_jitter_ratio):
            findings.append(
                finding(
                    "possible_beaconing",
                    "high",
                    "Regular network intervals with repeated connections may indicate beaconing or automation.",
                    src_ip=src,
                    dst_ip=dst,
                    connection_count=len(recs),
                    avg_interval_sec=round(avg_delta, 2),
                    interval_stddev=round(std_delta, 2),
                    avg_orig_bytes=round(mean(safe_int(r.get("orig_bytes")) for r in recs), 2),
                    avg_resp_bytes=round(mean(safe_int(r.get("resp_bytes")) for r in recs), 2),
                    sample_uids=[r.get("uid") for r in recs[:5]],
                )
            )

    return findings


# =========================
# Intel / TTP Hunts
# =========================

def hunt_known_bad_domains(
    dns_logs: list[dict[str, Any]],
    http_logs: list[dict[str, Any]],
    ssl_logs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    bad = {normalize_host(x) for x in CONFIG["known_bad_domains"]}

    for rec in dns_logs:
        query = normalize_host(rec.get("query", ""))
        if query in bad:
            findings.append(
                finding(
                    "known_bad_domain_dns",
                    "critical",
                    "DNS lookup for known malicious infrastructure.",
                    src_ip=rec.get("id.orig_h"),
                    query=query,
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    for rec in http_logs:
        host = normalize_host(rec.get("host", ""))
        if host in bad:
            findings.append(
                finding(
                    "known_bad_domain_http",
                    "critical",
                    "HTTP request to known malicious infrastructure.",
                    src_ip=rec.get("id.orig_h"),
                    dst_ip=rec.get("id.resp_h"),
                    host=host,
                    uri=rec.get("uri"),
                    method=rec.get("method"),
                    user_agent=rec.get("user_agent"),
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    for rec in ssl_logs:
        sni = normalize_host(rec.get("server_name", ""))
        if sni in bad:
            findings.append(
                finding(
                    "known_bad_domain_tls",
                    "critical",
                    "TLS connection to known malicious infrastructure.",
                    src_ip=rec.get("id.orig_h"),
                    dst_ip=rec.get("id.resp_h"),
                    server_name=sni,
                    subject=rec.get("subject"),
                    issuer=rec.get("issuer"),
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    return findings


def hunt_suspicious_uri(http_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    tokens = tuple(token.lower() for token in CONFIG["suspicious_uri_tokens"])

    for rec in http_logs:
        uri = str(rec.get("uri", ""))
        host = normalize_host(rec.get("host", ""))
        lower_uri = uri.lower()

        if any(token in lower_uri for token in tokens):
            findings.append(
                finding(
                    "suspicious_uri",
                    "medium",
                    "URI pattern resembles common lure, staging, or verification workflow.",
                    src_ip=rec.get("id.orig_h"),
                    dst_ip=rec.get("id.resp_h"),
                    host=host,
                    uri=uri,
                    method=rec.get("method"),
                    status_code=rec.get("status_code"),
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    return findings


def hunt_suspicious_script_delivery(http_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    exts = tuple(ext.lower() for ext in CONFIG["suspicious_script_extensions"])

    for rec in http_logs:
        uri = str(rec.get("uri", ""))
        host = normalize_host(rec.get("host", ""))
        method = rec.get("method", "")
        user_agent = str(rec.get("user_agent", ""))
        lower_uri = uri.lower()

        if method != "GET":
            continue

        if any(ext in lower_uri for ext in exts) or "captcha" in lower_uri:
            findings.append(
                finding(
                    "suspicious_script_delivery",
                    "high",
                    "Suspicious script or lure content retrieved over HTTP.",
                    src_ip=rec.get("id.orig_h"),
                    dst_ip=rec.get("id.resp_h"),
                    host=host,
                    uri=uri,
                    method=method,
                    user_agent=user_agent,
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    return findings


def hunt_possible_clickfix(http_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    for rec in http_logs:
        uri = str(rec.get("uri", ""))
        host = normalize_host(rec.get("host", ""))
        method = rec.get("method", "")
        user_agent = str(rec.get("user_agent", ""))

        suspicious_lure = (
            "captcha" in uri.lower()
            or "verify" in uri.lower()
            or ".js" in uri.lower()
        )

        weak_ua = not user_agent or len(user_agent.strip()) < 20

        if method == "GET" and suspicious_lure and weak_ua:
            findings.append(
                finding(
                    "possible_clickfix_stage",
                    "medium",
                    "Suspicious lure or script retrieval consistent with fake verification or ClickFix-style staging.",
                    src_ip=rec.get("id.orig_h"),
                    dst_ip=rec.get("id.resp_h"),
                    host=host,
                    uri=uri,
                    user_agent=user_agent,
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    return findings


def hunt_small_repeated_downloads(http_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    size_map: defaultdict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)

    for rec in http_logs:
        host = normalize_host(rec.get("host", ""))
        body_len = safe_int(rec.get("response_body_len"))
        if not host or body_len <= 0:
            continue
        size_map[(host, body_len)].append(rec)

    for (host, size), recs in size_map.items():
        if size <= CONFIG["small_download_max_bytes"] and len(recs) >= CONFIG["small_download_repeat_min"]:
            findings.append(
                finding(
                    "repeated_small_downloads",
                    "medium",
                    "Repeated small downloads may indicate staged payload retrieval or lure assets.",
                    host=host,
                    response_body_len=size,
                    count=len(recs),
                    sample_uris=[r.get("uri") for r in recs[:5]],
                    sample_uids=[r.get("uid") for r in recs[:5]],
                )
            )

    return findings


def hunt_rare_user_agents(http_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ua_counts = Counter()

    for rec in http_logs:
        ua = str(rec.get("user_agent", "")).strip()
        if ua:
            ua_counts[ua] += 1

    for rec in http_logs:
        ua = str(rec.get("user_agent", "")).strip()
        if not ua:
            continue
        if ua_counts[ua] == 1:
            findings.append(
                finding(
                    "rare_user_agent",
                    "low",
                    "User-Agent observed only once in this capture.",
                    src_ip=rec.get("id.orig_h"),
                    dst_ip=rec.get("id.resp_h"),
                    host=normalize_host(rec.get("host", "")),
                    uri=rec.get("uri"),
                    user_agent=ua,
                    uid=rec.get("uid"),
                    ts=rec.get("ts"),
                )
            )

    return findings


# =========================
# Enrichment
# =========================

def enrich_findings(
    findings: list[dict[str, Any]],
    dns_logs: list[dict[str, Any]],
    http_logs: list[dict[str, Any]],
    ssl_logs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    http_by_uid = get_uid_map(http_logs)
    ssl_by_uid = get_uid_map(ssl_logs)
    dns_by_uid = get_uid_map(dns_logs)

    enriched: list[dict[str, Any]] = []

    for item in findings:
        uid = item.get("uid")

        if uid and uid in dns_by_uid:
            rec = dns_by_uid[uid]
            item["dns"] = {
                "query": rec.get("query"),
                "answers": rec.get("answers"),
                "rcode_name": rec.get("rcode_name"),
            }

        if uid and uid in http_by_uid:
            rec = http_by_uid[uid]
            item["http"] = {
                "host": rec.get("host"),
                "uri": rec.get("uri"),
                "method": rec.get("method"),
                "user_agent": rec.get("user_agent"),
                "status_code": rec.get("status_code"),
                "resp_mime_types": rec.get("resp_mime_types"),
                "request_body_len": rec.get("request_body_len"),
                "response_body_len": rec.get("response_body_len"),
            }

        if uid and uid in ssl_by_uid:
            rec = ssl_by_uid[uid]
            item["ssl"] = {
                "server_name": rec.get("server_name"),
                "subject": rec.get("subject"),
                "issuer": rec.get("issuer"),
                "validation_status": rec.get("validation_status"),
                "ja3": rec.get("ja3"),
                "ja3s": rec.get("ja3s"),
            }

        enriched.append(item)

    return enriched


# =========================
# Output
# =========================

def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []

    for item in findings:
        key = json.dumps(
            {
                "type": item.get("type"),
                "uid": item.get("uid"),
                "src_ip": item.get("src_ip"),
                "dst_ip": item.get("dst_ip"),
                "query": item.get("query"),
                "host": item.get("host"),
                "uri": item.get("uri"),
                "server_name": item.get("server_name"),
            },
            sort_keys=True,
            default=str,
        )
        if key not in seen:
            seen.add(key)
            out.append(item)

    return out


def severity_rank(severity: str) -> int:
    order = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }
    return order.get(severity, 0)


def print_findings(findings: list[dict[str, Any]]) -> None:
    if not findings:
        print("[+] No findings produced by current heuristics.")
        return

    findings = sorted(findings, key=lambda x: severity_rank(str(x.get("severity", ""))), reverse=True)

    print(f"[+] Findings: {len(findings)}\n")

    for i, item in enumerate(findings[: CONFIG["print_max_findings"]], start=1):
        print("=" * 100)
        print(f"[{i}] {item.get('type')} | severity={item.get('severity')}")
        for key, value in item.items():
            if key in {"type", "severity"}:
                continue
            print(f"{key}: {value}")
        print()


def write_json(findings: list[dict[str, Any]], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, default=str)
    print(f"[INFO] Wrote JSON findings to: {path}")


# =========================
# Main
# =========================

def main() -> None:
    parser = argparse.ArgumentParser(description="Threat hunting over Zeek JSON logs derived from PCAP.")
    parser.add_argument("--logdir", required=True, help="Directory containing Zeek JSON logs")
    parser.add_argument("--json-out", help="Optional path to write findings as JSON")
    parser.add_argument("--baseline", action="store_true", help="Include baseline informational findings")
    args = parser.parse_args()

    logdir = Path(args.logdir)

    conn_logs = load_zeek_json_log(logdir / "conn.log")
    dns_logs = load_zeek_json_log(logdir / "dns.log")
    http_logs = load_zeek_json_log(logdir / "http.log")
    ssl_logs = load_zeek_json_log(logdir / "ssl.log")
    files_logs = load_zeek_json_log(logdir / "files.log")

    summarize_logs(conn_logs, dns_logs, http_logs, ssl_logs, files_logs)

    findings: list[dict[str, Any]] = []

    if args.baseline:
        findings.extend(baseline_external_connections(conn_logs))

    # Generic hunts
    findings.extend(hunt_dns_anomalies(dns_logs))
    findings.extend(hunt_suspicious_tlds(dns_logs))
    findings.extend(hunt_large_outbound(conn_logs))
    findings.extend(hunt_many_unique_externals(conn_logs))
    findings.extend(hunt_beaconing(conn_logs))
    findings.extend(hunt_rare_user_agents(http_logs))

    # Intel / TTP hunts
    findings.extend(hunt_known_bad_domains(dns_logs, http_logs, ssl_logs))
    findings.extend(hunt_suspicious_uri(http_logs))
    findings.extend(hunt_suspicious_script_delivery(http_logs))
    findings.extend(hunt_possible_clickfix(http_logs))
    findings.extend(hunt_small_repeated_downloads(http_logs))

    findings = dedupe_findings(findings)
    findings = enrich_findings(findings, dns_logs, http_logs, ssl_logs)

    print_findings(findings)

    if args.json_out:
        write_json(findings, Path(args.json_out))


if __name__ == "__main__":
    main()
