"""OWASP Agentic AI Top 10 reference scenarios for the AIVSS calculator."""

from __future__ import annotations

from typing import Any

from .ai_metrics import (
    AGENTIC_METRIC_ORDER,
    AGENTIC_METRICS,
    UNTRACEABILITY_FIELDS,
    classify_sr,
    parse_aivss_vector,
)
from .taxonomy import ASI_TOP_10
from .versions import CALCULATOR_VERSION

SCENARIOS: list[dict[str, Any]] = [
    {
        "finding_id": "AIVSS-ASI01-001",
        "risk_category": "ASI01",
        "title": "Direct prompt injection hijacks planning agent goals",
        "summary": "Attacker-supplied instructions override the agent's intended goals via a language-mediated control path.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N/E:P",
        "aivss_vector": "AIVSS:1.0/LC:D/CP:S/AP:C/SR:R/ES:M",
        "agent_untraceability": "Moderate",
        "publicly_exposed": True,
        "automatable": True,
        "technical_impact": "total",
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI02-001",
        "risk_category": "ASI02",
        "title": "Agent misuses legitimate tool for unauthorized data export",
        "summary": "A compromised or misled agent invokes an authorized tool outside its intended scope.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:N/SA:N/E:P",
        "aivss_vector": "AIVSS:1.0/LC:I/CP:N/AP:C/SR:R/ES:M",
        "agent_untraceability": "Low",
        "publicly_exposed": True,
        "automatable": True,
        "technical_impact": "total",
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI03-001",
        "risk_category": "ASI03",
        "title": "Stolen service credential used for lateral agent actions",
        "summary": "Abuse of agent identity or privileges to act on resources beyond the attacker's direct reach.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
        "aivss_vector": "AIVSS:1.0/LC:M/CP:N/AP:L/SR:R/ES:M",
        "agent_untraceability": "Low",
        "publicly_exposed": False,
        "automatable": True,
        "technical_impact": "total",
        "evidence": {"observed_local": True},
    },
    {
        "finding_id": "AIVSS-ASI04-001",
        "risk_category": "ASI04",
        "title": "Compromised MCP plugin supplies malicious tool definitions",
        "summary": "Untrusted supply-chain component alters agent capabilities or tool schemas at runtime.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:L/SA:N/E:P",
        "aivss_vector": "AIVSS:1.0/LC:I/CP:N/AP:L/SR:P/ES:W",
        "agent_untraceability": "Moderate",
        "publicly_exposed": True,
        "automatable": False,
        "technical_impact": "total",
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI05-001",
        "risk_category": "ASI05",
        "title": "Code interpreter executes attacker-supplied shell commands",
        "summary": "Agent reaches a code-execution path and runs attacker-controlled instructions.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P",
        "aivss_vector": "AIVSS:1.0/LC:D/CP:N/AP:N/SR:R/ES:M",
        "agent_untraceability": "Low",
        "publicly_exposed": True,
        "automatable": True,
        "technical_impact": "total",
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI06-001",
        "risk_category": "ASI06",
        "title": "Adversarial content in agent memory biases later sessions",
        "summary": "Poisoned context persists across sessions and influences future agent decisions.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P",
        "aivss_vector": "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/ES:W",
        "agent_untraceability": "High",
        "publicly_exposed": True,
        "automatable": True,
        "technical_impact": "total",
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI07-001",
        "risk_category": "ASI07",
        "title": "Unsigned agent-to-agent messages allow instruction relay",
        "summary": "Inter-agent messages lack authentication, enabling cross-agent propagation of malicious intent.",
        "cvss_vector": "CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:N/SC:H/SI:L/SA:N/E:P",
        "aivss_vector": "AIVSS:1.0/LC:I/CP:S/AP:L/SR:R/ES:W",
        "agent_untraceability": "Moderate",
        "publicly_exposed": False,
        "automatable": True,
        "technical_impact": "total",
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI08-001",
        "risk_category": "ASI08",
        "title": "Faulty planner triggers cascading downstream task failures",
        "summary": "A single agent fault propagates through orchestration to many dependent workflows.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:L/E:P",
        "aivss_vector": "AIVSS:1.0/LC:I/CP:S/AP:L/SR:P/ES:W",
        "agent_untraceability": "High",
        "publicly_exposed": True,
        "automatable": False,
        "technical_impact": "total",
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI09-001",
        "risk_category": "ASI09",
        "title": "Social engineering of human approver via forged agent summaries",
        "summary": "Attacker exploits human trust in agent-generated summaries to obtain unauthorized approvals.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:H/VA:N/SC:H/SI:N/SA:N/E:P",
        "aivss_vector": "AIVSS:1.0/LC:D/CP:N/AP:C/SR:P/ES:N",
        "agent_untraceability": "High",
        "publicly_exposed": True,
        "automatable": False,
        "technical_impact": "partial",
        "evidence": {"poc": True},
    },
    {
        "finding_id": "AIVSS-ASI10-001",
        "risk_category": "ASI10",
        "title": "Compromised worker agent operates outside policy envelope",
        "summary": "A rogue or hijacked agent continues autonomous operation beyond defined policy bounds.",
        "cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A",
        "aivss_vector": "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/ES:W",
        "agent_untraceability": "High",
        "publicly_exposed": True,
        "automatable": True,
        "technical_impact": "total",
        "evidence": {"observed_local": True},
    },
]


def scenario_by_id(asi_id: str) -> dict[str, Any]:
    upper = asi_id.strip().upper()
    for scenario in SCENARIOS:
        if scenario["risk_category"] == upper:
            return scenario
    raise KeyError(f"No reference scenario for {asi_id!r}")


def scenario_payload(
    asi_id: str, *, tool_version: str = CALCULATOR_VERSION
) -> dict[str, Any]:
    """Full synthetic assessment input for one OWASP ASI category."""
    scenario = scenario_by_id(asi_id)
    profile = parse_aivss_vector(scenario["aivss_vector"])
    metric_evidence = {}
    for name in AGENTIC_METRIC_ORDER:
        value = getattr(profile, name.lower())
        if name == "SR" and value == "R":
            detail = (
                "A production-equivalent fixture records 30 successful "
                "independent episodes out of 30, each from clean state with the "
                "hard production budget of three attempts for one stable principal; "
                "the one-sided 95% Wilson lower bound is 0.917."
            )
        elif name == "SR" and value == "P":
            detail = (
                "A production-equivalent fixture records 18 successful "
                "independent episodes out of 30, each from clean state with the "
                "hard production budget of three attempts for one stable principal; "
                "one-sided 95% Wilson bounds are 0.451 and 0.733. Repeated attempts "
                "are needed, so the CVSS vector records AT:P."
            )
        else:
            detail = AGENTIC_METRICS[name][value][1]
        record: dict[str, Any] = {
            "rationale": (
                f"Synthetic reference fact for {scenario['finding_id']}: {detail}"
            ),
            "evidence_refs": [
                f"fixture://{scenario['finding_id']}/{name.lower()}"
            ],
        }
        if name == "SR":
            if value in {"R", "P", "U"}:
                successes = {"R": 30, "P": 18, "U": 0}[value]
                result = classify_sr(
                    successes=successes,
                    episodes=30,
                    production_equivalent=True,
                    budget_enforced=True,
                    independent=True,
                )
                record.update(
                    {
                        "method": "empirical",
                        "successes": successes,
                        "episodes": 30,
                        "retry_budget": 3,
                        "production_equivalent": True,
                        "budget_enforced": True,
                        "independent": True,
                        "lower_bound": result.lower_bound,
                        "upper_bound": result.upper_bound,
                    }
                )
            else:
                record["method"] = "insufficient-evidence"
        metric_evidence[name] = record
    untraceability = scenario["agent_untraceability"]
    observations = {
        "High": (True, False, False, False, False, False),
        "Moderate": (True, True, True, False, False, False),
        "Low": (True, True, True, True, True, True),
        "X": (False, None, None, None, None, None),
    }[untraceability]
    untraceability_detail = {
        "High": "A retrieval test cannot reconstruct ordered actions or bound affected principals.",
        "Moderate": (
            "A retrieval test reconstructs ordered actions and principals but finds "
            "missing integrity or retention evidence."
        ),
        "Low": (
            "A retrieval exercise verifies all required correlated, "
            "integrity-protected, and retained records."
        ),
        "X": "No retrieval exercise has been completed.",
    }[untraceability]
    agent_untraceability: dict[str, Any] = {
        "rationale": (
            f"Synthetic reference fact for {scenario['finding_id']}: "
            f"{untraceability_detail}"
        ),
        "evidence_refs": [f"fixture://{scenario['finding_id']}/untraceability"],
        **dict(zip(UNTRACEABILITY_FIELDS, observations, strict=True)),
    }
    payload = {key: val for key, val in scenario.items() if key != "agent_untraceability"}
    return {
        **payload,
        "agent_untraceability": agent_untraceability,
        "path_id": f"{scenario['finding_id']}-PATH-1",
        "agentic_applicability": {
            "model_directed_goal_pursuit": True,
            "action_selection_or_sequencing": True,
            "rationale": (
                "The synthetic fixture uses a model to pursue a delegated goal and "
                "select or sequence actions that affect its environment."
            ),
            "evidence_refs": [
                f"fixture://{scenario['finding_id']}/agentic-applicability"
            ],
        },
        "publicly_exposed_source": "synthetic deployment inventory fixture",
        "decision_data_observed_at": "2026-08-27T00:00:00Z",
        "metric_evidence": metric_evidence,
        "include_decision": True,
        "include_priority": False,
        "provenance": {
            "assessor": "synthetic-reference-fixture",
            "assessor_kind": "imported",
            "tool": "aivss-calc",
            "tool_version": tool_version,
            "assessed_at": "2026-08-27T00:00:00Z",
        },
    }


def scenario_catalog() -> list[dict[str, Any]]:
    """Metadata for every OWASP ASI category in display order."""
    return [
        {
            "id": s["risk_category"],
            "name": ASI_TOP_10[s["risk_category"]],
            "title": s["title"],
            "summary": s["summary"],
        }
        for s in SCENARIOS
    ]
