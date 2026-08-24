from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from keel.catalog.fingerprint import (
    canonical_vulnerability_class,
    fingerprint,
    load_json_lines,
    split_url,
)
from keel.models import EvidenceStrength, FindingCard, ValidationState
from keel.proof.sanitize import sanitize_evidence
from keel.triage.exploitability import assess_card
from keel.triage.filters import impact_from_severity, severity_of_nuclei


def invalid_nuclei_record_count(stdout: str) -> int:
    invalid = 0
    for row in load_json_lines(stdout):
        matched = row.get("matched-at") or row.get("host")
        template_id = row.get("template-id")
        if (
            not isinstance(matched, str)
            or not matched.strip()
            or not isinstance(template_id, str)
            or not template_id.strip()
        ):
            invalid += 1
    return invalid


def cards_from_nuclei(stdout: str) -> list[FindingCard]:
    cards: list[FindingCard] = []
    for row in load_json_lines(stdout):
        matched = str(row.get("matched-at") or row.get("host") or "")
        host, path = split_url(matched)
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        name = str(info.get("name") or row.get("template-id") or "nuclei")
        template = str(row.get("template-id") or name)
        severity = severity_of_nuclei(info.get("severity") or row.get("severity"))
        classification = (
            info.get("classification")
            if isinstance(info.get("classification"), dict)
            else {}
        )
        cwes = _as_strings(classification.get("cwe-id"))
        tags = _as_strings(info.get("tags"))
        vulnerability_class = canonical_vulnerability_class(template, name, cwes, tags)
        parameter = _parameter_key(matched)
        method = _request_method(row)
        fp = fingerprint(vulnerability_class, host, path, f"{method}:{parameter}")
        cards.append(
            assess_card(FindingCard(
                card_id=fp,
                fingerprint=fp,
                host=host,
                path=path,
                matcher=template,
                title=name,
                scanner_severity=severity,
                impact_class=impact_from_severity(
                    severity, template, name, vulnerability_class
                ),
                evidence={"matched": matched, "raw": sanitize_evidence(row)},
                sources=["nuclei"],
                semantic_key=fp,
                vulnerability_class=vulnerability_class,
                parameter=parameter,
                method=method,
                validation_state=ValidationState.HYPOTHESIS,
                evidence_strength=EvidenceStrength.SINGLE_SOURCE,
            ))
        )
    return cards


def _as_strings(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip().lower() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip().lower() for item in value.split(",") if item.strip()]
    return []


def _parameter_key(url: str) -> str:
    query_names = sorted({name.lower() for name, _ in parse_qsl(urlparse(url).query)})
    return ",".join(query_names)


def _request_method(row: dict) -> str:
    request = row.get("request") if isinstance(row.get("request"), dict) else {}
    method = str(request.get("method") or row.get("method") or "GET").upper()
    return method if method in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"} else "GET"
