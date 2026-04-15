from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI(title="pcaphunter backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ZEEK_BIN = os.environ.get("PCAPHUNTER_ZEEK_BIN", "/opt/zeek/bin/zeek")
DEFAULT_RULES_PATH = os.environ.get(
    "PCAPHUNTER_RULES_PATH",
    "/home/node/.n8n-files/pcap-hunter/staging_rules.json",
)


def safe_read_json_lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def read_rules_file(path: str) -> list[dict[str, Any]]:
    rules_path = Path(path)
    if not rules_path.exists():
        return []
    try:
        data = json.loads(rules_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read rules file: {exc}")

    rules = data.get("rules", [])
    return rules if isinstance(rules, list) else []


IOC_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def parse_user_iocs(raw: str) -> list[dict[str, Any]]:
    raw = raw.strip()
    if not raw:
        return []

    parts = [p.strip() for p in re.split(r"[\n,]", raw) if p.strip()]
    rules: list[dict[str, Any]] = []

    for idx, part in enumerate(parts, start=1):
        if IOC_IPV4_RE.fullmatch(part):
            rules.append(
                {
                    "id": f"USER-IOC-IP-{idx}",
                    "name": f"User IOC IP {part}",
                    "description": "User-supplied destination IP IOC.",
                    "log_type": "conn",
                    "enabled": True,
                    "severity": "high",
                    "logic": {
                        "type": "exact_match",
                        "field": "id.resp_h",
                        "values": [part],
                    },
                    "tags": ["user_ioc", "ip"],
                    "references": ["user_upload"],
                }
            )
        elif IOC_DOMAIN_RE.fullmatch(part.lower()):
            rules.append(
                {
                    "id": f"USER-IOC-DOMAIN-{idx}",
                    "name": f"User IOC domain {part}",
                    "description": "User-supplied domain IOC.",
                    "log_type": "http",
                    "enabled": True,
                    "severity": "high",
                    "logic": {
                        "type": "exact_match",
                        "field": "host",
                        "values": [part.lower()],
                    },
                    "tags": ["user_ioc", "domain"],
                    "references": ["user_upload"],
                }
            )

    return rules


def normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def get_record_value(record: dict[str, Any], field: str) -> Any:
    return record.get(field)


def record_matches_logic(record: dict[str, Any], logic: dict[str, Any]) -> bool:
    rule_type = logic.get("type")
    field = logic.get("field")
    values = logic.get("values", [])
    value = get_record_value(record, field)

    if rule_type == "exists":
        return value not in (None, "", [])

    if value is None:
        return False

    text = normalize_text(value)
    norm_values = [normalize_text(v) for v in values]

    if rule_type == "exact_match":
        return text in norm_values
    if rule_type == "substring_match":
        return any(v in text for v in norm_values)
    if rule_type == "domain_suffix_match":
        return any(text.endswith(v) for v in norm_values)
    if rule_type == "regex_match":
        return any(re.search(pattern, str(value), re.I) for pattern in values)
    if rule_type == "list_contains":
        if isinstance(value, list):
            lower_items = {normalize_text(v) for v in value}
            return any(v in lower_items for v in norm_values)
        return text in norm_values
    if rule_type == "numeric_gte":
        try:
            return float(value) >= float(logic.get("value", 0))
        except Exception:
            return False
    if rule_type == "numeric_lte":
        try:
            return float(value) <= float(logic.get("value", 0))
        except Exception:
            return False

    return False


def severity_weight(severity: str) -> int:
    return {
        "critical": 60,
        "high": 25,
        "medium": 10,
        "low": 5,
        "info": 1,
    }.get(severity.lower(), 0)


def verdict_from_findings(findings: list[dict[str, Any]]) -> str:
    total_score = sum(int(f.get("score", 0)) for f in findings)
    severities = {normalize_text(f.get("severity")) for f in findings}

    if "critical" in severities or total_score >= 60:
        return "MALICIOUS"
    if "high" in severities or total_score >= 35:
        return "UNWANTED"
    if "medium" in severities or total_score >= 15:
        return "INTERESTING"
    if total_score > 0:
        return "BENIGN"
    return "LEGITIMATE"


def build_hit(rule: dict[str, Any], record: dict[str, Any]) -> str:
    logic = rule.get("logic", {})
    field = logic.get("field", "field")
    values = logic.get("values", [])
    if logic.get("type") == "exact_match" and values:
        return f'{field} == "{values[0]}"'
    if logic.get("type") == "substring_match" and values:
        return f'{field} ~= "{values[0]}"'
    if logic.get("type") == "domain_suffix_match" and values:
        return f'{field} endswith "{values[0]}"'
    return f"{field} matched"


def map_logs(logdir: Path) -> dict[str, list[dict[str, Any]]]:
    return {
        "conn": safe_read_json_lines(logdir / "conn.log"),
        "dns": safe_read_json_lines(logdir / "dns.log"),
        "http": safe_read_json_lines(logdir / "http.log"),
        "ssl": safe_read_json_lines(logdir / "ssl.log"),
        "files": safe_read_json_lines(logdir / "files.log"),
    }


def build_indicators(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []

    for f in findings:
        dst = str(f.get("dst", "")).strip()
        if not dst:
            continue
        indicator_type = "IP" if IOC_IPV4_RE.fullmatch(dst) else "DOMAIN" if "." in dst and "/" not in dst else "URI"
        key = (indicator_type, dst)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "type": indicator_type,
            "value": dst,
            "confidence": "HIGH" if f.get("severity") in {"critical", "high"} else "MED",
        })
    return out


def run_rules(logs: dict[str, list[dict[str, Any]]], rules: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    findings: list[dict[str, Any]] = []
    raw_logs: dict[str, list[str]] = {}
    counter = 1

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        log_type = rule.get("log_type")
        logic = rule.get("logic", {})
        for record in logs.get(log_type, []):
            if not record_matches_logic(record, logic):
                continue

            finding_id = f"F-{counter:03d}"
            counter += 1
            severity = normalize_text(rule.get("severity", "medium")) or "medium"
            src = str(record.get("id.orig_h", ""))
            dst = str(record.get("id.resp_h", "")) or str(record.get("host", "")) or str(record.get("server_name", "")) or str(record.get("uri", ""))

            findings.append(
                {
                    "id": finding_id,
                    "severity": severity,
                    "title": str(rule.get("name", "RULE MATCH")).upper(),
                    "summary": str(rule.get("description", "Matched rule.")).strip(),
                    "src": src,
                    "dst": dst,
                    "score": severity_weight(severity),
                    "hit": build_hit(rule, record),
                    "context": f"Matched {log_type}.log via rule {rule.get('id', 'unknown')}",
                    "rule_id": rule.get("id", ""),
                }
            )

            raw_logs[finding_id] = [json.dumps(record, ensure_ascii=False)]

    return findings, raw_logs


def run_zeek(pcap_path: Path, outdir: Path) -> None:
    cmd = [ZEEK_BIN, "-C", "-r", str(pcap_path), "LogAscii::use_json=T"]
    try:
        subprocess.run(
            cmd,
            cwd=str(outdir),
            capture_output=True,
            text=True,
            check=True,
            timeout=300,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=f"Zeek binary not found: {exc}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Zeek analysis timed out.")
    except subprocess.CalledProcessError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "message": "Zeek failed.",
                "stderr": exc.stderr[-4000:],
                "stdout": exc.stdout[-4000:],
            },
        )


@app.get("/health")
def health() -> dict[str, str]:
    return {"ok": "true"}


@app.post("/analyze")
async def analyze(
    pcap: UploadFile = File(...),
    user_iocs: str = Form(default=""),
    rules_path: str = Form(default=DEFAULT_RULES_PATH),
) -> JSONResponse:
    suffix = Path(pcap.filename or "upload.pcap").suffix or ".pcap"

    with tempfile.TemporaryDirectory(prefix="pcaphunter_") as temp_dir:
        temp_root = Path(temp_dir)
        pcap_path = temp_root / f"upload{suffix}"
        zeek_out = temp_root / "zeek_out"
        zeek_out.mkdir(parents=True, exist_ok=True)

        with pcap_path.open("wb") as f:
            shutil.copyfileobj(pcap.file, f)

        run_zeek(pcap_path, zeek_out)
        logs = map_logs(zeek_out)

        stored_rules = read_rules_file(rules_path)
        ad_hoc_rules = parse_user_iocs(user_iocs)
        all_rules = stored_rules + ad_hoc_rules

        findings, raw_logs = run_rules(logs, all_rules)
        verdict = verdict_from_findings(findings)
        indicators = build_indicators(findings)

        return JSONResponse(
            {
                "verdict": verdict,
                "findings": findings,
                "indicators": indicators,
                "raw_logs": raw_logs,
                "meta": {
                    "rules_loaded": len(all_rules),
                    "stored_rules_loaded": len(stored_rules),
                    "ad_hoc_rules_loaded": len(ad_hoc_rules),
                    "log_counts": {k: len(v) for k, v in logs.items()},
                },
            }
        )

