"""The AIVSS 1.0 Agentic AI profile (AIVSS 1.0 specification).

Five categorical metrics describe residual agentic properties that CVSS-BTE does
not measure. LC, CP, AP and SR assign the Agentic Effect Class by an ordered
rule ladder (A2, A1, AX, A0; first match wins). ES enters only Lookup Table U.
Agent untraceability is mandatory report metadata and never changes a score.

Labels are ordinal categories, never numbers: no arithmetic is performed on
them. Legacy eight-metric vectors (EX, PT, CA, TD) are accepted only through
``convert_legacy_vector`` for migration.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from .versions import EXTENSION_VECTOR_VERSION

AIVSS_EXTENSION_VERSION = EXTENSION_VECTOR_VERSION
AIVSS_EXTENSION_PREFIX = f"AIVSS:{AIVSS_EXTENSION_VERSION}"
EFFECT_CLASS_STATUS = "candidate-unvalidated"
UNKNOWN_VALUE = "X"

LC_VALUES: dict[str, tuple[str, str]] = {
    "D": (
        "Direct",
        "Attacker-supplied natural language reaches a privileged decision or "
        "tool-invocation path without mediation.",
    ),
    "I": (
        "Indirect",
        "Attacker-controlled language enters through retrieved or ingested content "
        "(documents, web pages, email, files) and influences security-relevant behaviour.",
    ),
    "M": (
        "Mediated",
        "An independently enforced transformation reduces language to closed, "
        "validated fields before every security-relevant sink.",
    ),
    "N": ("None", "No natural-language path to security-relevant behaviour."),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine the language-control path.",
    ),
}

CP_VALUES: dict[str, tuple[str, str]] = {
    "C": (
        "Cross-session memory",
        "Attacker-controlled context or memory persists in durable stores — vector "
        "databases, long-term agent memory, episodic memory banks, RAG indexes, "
        "user profiles, or training/fine-tuning data — and remains reachable after "
        "the originating session ends.",
    ),
    "S": (
        "Session context",
        "Attacker-controlled context persists only in ephemeral session state "
        "(conversation buffer, in-memory working context, session-scoped cache), and "
        "testing confirms it is unreachable after the session boundary.",
    ),
    "N": (
        "None",
        "Single-turn or stateless; no attacker-controlled context or memory carryover "
        "between requests.",
    ),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine context or memory persistence.",
    ),
}

AP_VALUES: dict[str, tuple[str, str]] = {
    "L": (
        "Lateral",
        "Compromised intent or authority crosses a trust boundary into another agent, "
        "tenant, principal or policy domain. Impact on downstream systems is scored "
        "in CVSS SC/SI/SA, not here.",
    ),
    "C": (
        "Contained",
        "Influence relays across agent components under the same principal and policy "
        "domain without crossing a trust boundary.",
    ),
    "N": ("None", "Effect is confined to the initially affected component."),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine propagation scope.",
    ),
}

SR_VALUES: dict[str, tuple[str, str]] = {
    "R": (
        "Reliable",
        "A deterministic proof guarantees success, or the one-sided 95% Wilson lower "
        "bound implies at least 90% cumulative success within the enforced production "
        "retry budget.",
    ),
    "P": (
        "Probabilistic",
        "At least 30 representative attempts exist and the confidence bounds support "
        "neither the Reliable nor Unreliable threshold.",
    ),
    "U": (
        "Unreliable",
        "A deterministic proof excludes success, or the one-sided 95% Wilson upper "
        "bound implies less than 10% cumulative success within the enforced production "
        "retry budget.",
    ),
    "X": (
        "Insufficient evidence",
        "No representative retry-budget evidence is available.",
    ),
}

ES_VALUES: dict[str, tuple[str, str]] = {
    "W": (
        "Wide",
        "A reachable tool, MCP server, skill or plugin is dynamic or unvetted, or its "
        "identity, callable operations, arguments or credentials are not independently "
        "constrained on the assessed path.",
    ),
    "M": (
        "Managed",
        "Extensions are allowlisted, but material gaps remain in argument schemas, "
        "credentials or callable operations.",
    ),
    "N": (
        "None or narrow",
        "No security-relevant dynamic extension on the path, or a fixed, allowlisted, "
        "least-privilege binding enforced outside model output.",
    ),
    "X": (
        "Insufficient evidence",
        "Available evidence cannot determine the extension binding surface.",
    ),
}

EX_VALUES = ES_VALUES  # legacy alias (AIVSS 1.0 draft name for ES)

PT_VALUES: dict[str, tuple[str, str]] = {
    "H": (
        "High deficit",
        "Runtime controls do not enforce the approved provider, model, and deployment "
        "configuration, or routing can change them outside authorized change control.",
    ),
    "M": (
        "Moderate deficit",
        "Provider, model, and deployment configuration are enforced and changes are "
        "auditable, but the served artifact or provider-side content cannot be "
        "independently verified at runtime.",
    ),
    "L": (
        "Low deficit",
        "Provider, model, and deployment configuration are enforced; artifact identity "
        "or equivalent attestation is verified; changes require recorded authorization.",
    ),
    "X": ("Insufficient evidence", "Model/provider provenance cannot be established."),
}

CA_VALUES: dict[str, tuple[str, str]] = {
    "W": (
        "Wide",
        "No finite hard aggregate ceiling exists for attacker-triggered consumption, "
        "or testing demonstrates a bypass.",
    ),
    "M": (
        "Moderate",
        "A finite hard ceiling exists and no bypass is demonstrated, but coverage is "
        "incomplete or enforcement is not fail-closed.",
    ),
    "N": (
        "Narrow",
        "Tested fail-closed aggregate limits cover tokens, paid calls, compute, retries, "
        "fan-out, queued work, and concurrency for a stable principal and tenant.",
    ),
    "X": (
        "Insufficient evidence",
        "Aggregate economic limits on the path are unknown.",
    ),
}

TD_VALUES: dict[str, tuple[str, str]] = {
    "H": (
        "High deficit",
        "Testing confirms responders cannot reconstruct ordered security-relevant "
        "actions or bound affected principals from retained records.",
    ),
    "M": (
        "Moderate deficit",
        "The ordered path and affected principals are reconstructable, but required "
        "fields, correlation, integrity, or tested retention controls are incomplete.",
    ),
    "L": (
        "Low deficit",
        "A retrieval exercise verifies correlated, integrity-protected records of inputs, "
        "context references, model identity, policy decisions, calls, and outcomes.",
    ),
    "X": (
        "Insufficient evidence",
        "Audit-log coverage and retention cannot be established.",
    ),
}

@dataclass(frozen=True)
class SRClassification:
    """Reproducible result of the empirical SR decision rule."""

    value: str
    lower_bound: float | None
    upper_bound: float | None
    method: str


def classify_sr(
    *,
    successes: int | None = None,
    episodes: int | None = None,
    production_equivalent: bool = False,
    budget_enforced: bool = False,
    independent: bool = False,
    deterministic_outcome: str | None = None,
) -> SRClassification:
    """Classify SR using the rubric's proof or one-sided Wilson rule."""
    if deterministic_outcome is not None:
        if deterministic_outcome == "success":
            return SRClassification("R", 1.0, 1.0, "deterministic-proof")
        if deterministic_outcome == "failure":
            return SRClassification("U", 0.0, 0.0, "deterministic-proof")
        raise ValueError("deterministic_outcome must be success, failure, or omitted")

    for name, value in (
        ("production_equivalent", production_equivalent),
        ("budget_enforced", budget_enforced),
        ("independent", independent),
    ):
        if type(value) is not bool:
            raise ValueError(f"{name} must be true or false")
    if successes is None or episodes is None:
        return SRClassification("X", None, None, "insufficient-evidence")
    if type(successes) is not int or type(episodes) is not int:
        raise ValueError("successes and episodes must be integers")
    if episodes <= 0 or not 0 <= successes <= episodes:
        raise ValueError(
            "episodes must be positive and successes must be in [0, episodes]"
        )
    if (
        episodes < 30
        or not production_equivalent
        or not budget_enforced
        or not independent
    ):
        return SRClassification("X", None, None, "insufficient-evidence")

    n = Decimal(episodes)
    p = Decimal(successes) / n
    z = Decimal("1.645")
    denominator = Decimal(1) + (z**2 / n)
    center = (p + z**2 / (Decimal(2) * n)) / denominator
    margin = (
        z / denominator * (p * (Decimal(1) - p) / n + z**2 / (Decimal(4) * n**2)).sqrt()
    )
    lower = max(Decimal(0), center - margin)
    upper = min(Decimal(1), center + margin)
    if lower >= Decimal("0.90"):
        value = "R"
    elif upper < Decimal("0.10"):
        value = "U"
    else:
        value = "P"
    return SRClassification(value, float(lower), float(upper), "wilson-one-sided-95")


def classify_ca(
    *,
    ceiling_defined: bool | None,
    coverage_complete: bool | None,
    fail_closed: bool | None,
    bypass_demonstrated: bool | None,
) -> str:
    """Classify cost-abuse containment from policy-independent control facts."""
    values = {
        "ceiling_defined": ceiling_defined,
        "coverage_complete": coverage_complete,
        "fail_closed": fail_closed,
        "bypass_demonstrated": bypass_demonstrated,
    }
    for name, value in values.items():
        if value is not None and type(value) is not bool:
            raise ValueError(f"{name} must be true, false, or unknown")
    if bypass_demonstrated is True or ceiling_defined is False:
        return "W"
    if bypass_demonstrated is None or ceiling_defined is None:
        return "X"
    if coverage_complete is None or fail_closed is None:
        return "X"
    if coverage_complete and fail_closed:
        return "N"
    return "M"


def classify_td(
    *,
    retrieval_tested: bool | None,
    ordered_actions_reconstructable: bool | None,
    affected_principals_bounded: bool | None,
    required_fields_complete: bool | None,
    integrity_protected: bool | None,
    retention_verified: bool | None,
) -> str:
    """Classify traceability from a retrieval exercise and observable controls."""
    values = {
        "retrieval_tested": retrieval_tested,
        "ordered_actions_reconstructable": ordered_actions_reconstructable,
        "affected_principals_bounded": affected_principals_bounded,
        "required_fields_complete": required_fields_complete,
        "integrity_protected": integrity_protected,
        "retention_verified": retention_verified,
    }
    for name, value in values.items():
        if value is not None and type(value) is not bool:
            raise ValueError(f"{name} must be true, false, or unknown")
    if retrieval_tested is not True:
        return "X"
    if (
        ordered_actions_reconstructable is False
        or affected_principals_bounded is False
    ):
        return "H"
    if (
        ordered_actions_reconstructable is None
        or affected_principals_bounded is None
        or required_fields_complete is None
        or integrity_protected is None
        or retention_verified is None
    ):
        return "X"
    if required_fields_complete and integrity_protected and retention_verified:
        return "L"
    return "M"




def classify_untraceability(**observations: bool | None) -> str:
    """Agent untraceability value (High, Moderate, Low or X) from a retrieval exercise."""
    return UNTRACEABILITY_LABELS[classify_td(**observations)]


UNTRACEABILITY_LABELS: dict[str, str] = {
    "H": "High",
    "M": "Moderate",
    "L": "Low",
    "X": "X",
}
UNTRACEABILITY_CODES: dict[str, str] = {v: k for k, v in UNTRACEABILITY_LABELS.items()}
UNTRACEABILITY_FIELDS: tuple[str, ...] = (
    "retrieval_tested",
    "ordered_actions_reconstructable",
    "affected_principals_bounded",
    "required_fields_complete",
    "integrity_protected",
    "retention_verified",
)
UNTRACEABILITY_DEFINITIONS: dict[str, str] = {
    "High": (
        "A retrieval exercise cannot reconstruct the ordered security-relevant "
        "actions on the path or cannot bound the affected principals."
    ),
    "Moderate": (
        "Both can be reconstructed, but required fields, integrity protection of "
        "the records, or verified retention is missing."
    ),
    "Low": (
        "Both can be reconstructed, required fields are complete, the records are "
        "integrity-protected, and retention is verified."
    ),
    "X": "No completed retrieval exercise.",
}

CLASSIFYING_AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    "LC": LC_VALUES,
    "CP": CP_VALUES,
    "AP": AP_VALUES,
    "SR": SR_VALUES,
}

# ES is the only metric that is not a classifying input; it enters Table 5 (U).
UPLIFT_AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {"ES": ES_VALUES}
ASSURANCE_AGENTIC_METRICS = UPLIFT_AGENTIC_METRICS  # backward-compatible name
ADJUSTMENT_AGENTIC_METRICS = UPLIFT_AGENTIC_METRICS

AGENTIC_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    **CLASSIFYING_AGENTIC_METRICS,
    **UPLIFT_AGENTIC_METRICS,
}

AI_METRICS = AGENTIC_METRICS

AGENTIC_METRIC_ORDER: tuple[str, ...] = ("LC", "CP", "AP", "SR", "ES")
AI_METRIC_ORDER = AGENTIC_METRIC_ORDER

# Draft eight-metric order (pre-1.0), accepted only for migration.
LEGACY_METRIC_ORDER: tuple[str, ...] = ("LC", "CP", "AP", "SR", "EX", "PT", "CA", "TD")
LEGACY_METRICS: dict[str, dict[str, tuple[str, str]]] = {
    **CLASSIFYING_AGENTIC_METRICS,
    "EX": ES_VALUES,
    "PT": PT_VALUES,
    "CA": CA_VALUES,
    "TD": TD_VALUES,
}

AGENTIC_METRIC_NAMES: dict[str, str] = {
    "LC": "Language-Mediated Control",
    "CP": "Context Persistence",
    "AP": "Agentic Control Propagation",
    "SR": "Stochastic Exploit Reliability",
    "ES": "Extension Binding Surface",
}

AGENTIC_METRIC_SUMMARIES: dict[str, str] = {
    "LC": (
        "How directly attacker-controlled natural language reaches a "
        "security-relevant decision or tool call."
    ),
    "CP": (
        "How long attacker-controlled context or memory survives, and whether it "
        "outlives the session that introduced it."
    ),
    "AP": (
        "Whether compromised intent or authority crosses a trust boundary into "
        "another agent, tenant, principal or policy domain."
    ),
    "SR": (
        "How reliably the exploit succeeds within the production retry budget. "
        "SR refines CVSS AT and must agree with it: SR:P or SR:U requires AT:P."
    ),
    "ES": (
        "How tightly the tools, skills, MCP servers and plugins reachable on the "
        "path are bound. ES enters Lookup Table U only."
    ),
}

AGENTIC_EFFECT_CLASS_LABELS: dict[str, str] = {
    "A0": "None",
    "A1": "Present",
    "A2": "Substantial",
    "AX": "Insufficient evidence",
}

# Lookup Table U (Table 5): Effect Class key x ES. AX uses the A0 row.
UPLIFT_TABLE: dict[str, dict[str, int]] = {
    "A0": {"N": 0, "M": 1, "W": 2},
    "A1": {"N": 3, "M": 5, "W": 6},
    "A2_not_R": {"N": 7, "M": 8, "W": 9},
    "A2_R": {"N": 8, "M": 9, "W": 10},
}


@dataclass(frozen=True)
class AIProfile:
    """One coherent exploit-path profile: LC, CP, AP, SR and ES."""

    lc: str
    cp: str
    ap: str
    sr: str
    es: str

    def __post_init__(self) -> None:
        for name in AGENTIC_METRIC_ORDER:
            value = getattr(self, name.lower())
            if value not in AGENTIC_METRICS[name]:
                raise ValueError(
                    f"Illegal value {value!r} for Agentic AI metric {name!r}; "
                    f"expected one of {sorted(AGENTIC_METRICS[name])}"
                )

    @property
    def ex(self) -> str:  # legacy accessor
        return self.es

    @property
    def complete(self) -> bool:
        return all(
            getattr(self, name.lower()) != UNKNOWN_VALUE
            for name in AGENTIC_METRIC_ORDER
        )

    @property
    def provisional(self) -> bool:
        """True when any classifying metric (LC, CP, AP or SR) is X."""
        return any(
            getattr(self, name.lower()) == UNKNOWN_VALUE
            for name in CLASSIFYING_AGENTIC_METRICS
        )

    def agentic_effect_class(self) -> str:
        return self.effect_class()

    def effect_class(self) -> str:
        """Ordered rule ladder (AIVSS 1.0 specification, Section 5.6).

        A clause applies when its own metrics are known, even if another
        classifying metric is X, so missing evidence never lowers the class
        below what the known evidence supports.
        """
        lc, cp, ap, sr = self.lc, self.cp, self.ap, self.sr
        if ap == "L" or (lc in ("D", "I") and cp == "C") or (lc == "D" and sr == "R"):
            return "A2"
        if lc in ("D", "I") or cp in ("S", "C") or ap == "C":
            return "A1"
        if UNKNOWN_VALUE in (lc, cp, ap):
            return "AX"
        return "A0"

    def agentic_uplift_u(self) -> int | None:
        """Lookup Table U (Table 5). Informative; returns None when ES is X."""
        if self.es == UNKNOWN_VALUE:
            return None
        effect = self.effect_class()
        if effect == "A2":
            key = "A2_R" if self.sr == "R" else "A2_not_R"
        elif effect == "A1":
            key = "A1"
        else:
            key = "A0"
        return UPLIFT_TABLE[key][self.es]

    def to_vector_fragment(self) -> str:
        return "/".join(
            f"{name}:{getattr(self, name.lower())}" for name in AGENTIC_METRIC_ORDER
        )

    def to_vector(self) -> str:
        return f"{AIVSS_EXTENSION_PREFIX}/{self.to_vector_fragment()}"

    def describe(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for name in AGENTIC_METRIC_ORDER:
            value = getattr(self, name.lower())
            out[name] = f"{value} ({AGENTIC_METRICS[name][value][0]})"
        return out


def check_sr_at(sr: str, at: str) -> None:
    """SR must agree with CVSS AT (AIVSS 1.0 specification, Section 4.3).

    FIRST defines AT:P to include attacks that may need to be launched
    multiple times against a single target, so SR:P or SR:U requires AT:P.
    Pass the effective value: MAT overrides AT when it is set.
    """
    if sr in ("P", "U") and at != "P":
        raise ValueError(
            f"SR:{sr} requires CVSS AT:P (or MAT:P when MAT is set): an exploit "
            "that needs repeated attempts meets FIRST's Attack Requirements "
            "Present definition"
        )


def validate_metric_evidence(
    profile: AIProfile, evidence: dict[str, dict[str, Any]]
) -> None:
    """Validate evidence shape and the executable SR classification facts."""
    expected_metrics = set(AGENTIC_METRIC_ORDER)
    if not isinstance(evidence, dict) or set(evidence) != expected_metrics:
        raise ValueError("metric_evidence must contain exactly LC, CP, AP, SR, and ES")
    common = {"rationale", "evidence_refs"}
    sr_fields = {
        "method",
        "deterministic_outcome",
        "successes",
        "episodes",
        "retry_budget",
        "production_equivalent",
        "budget_enforced",
        "independent",
        "lower_bound",
        "upper_bound",
    }
    for name in AGENTIC_METRIC_ORDER:
        entry = evidence[name]
        _check_common_evidence(name, entry)
        allowed = common | sr_fields if name == "SR" else common
        extras = set(entry) - allowed
        if extras:
            raise ValueError(f"{name} evidence has unknown fields: {sorted(extras)}")

    sr = evidence["SR"]
    method = sr.get("method")
    if method == "deterministic-proof":
        result = classify_sr(deterministic_outcome=sr.get("deterministic_outcome"))
        required = common | {"method", "deterministic_outcome"}
    elif method == "empirical":
        required = common | (sr_fields - {"deterministic_outcome"})
        missing = required - set(sr)
        if missing:
            raise ValueError(f"SR empirical evidence is missing {sorted(missing)}")
        retry_budget = sr["retry_budget"]
        if type(retry_budget) is not int or retry_budget < 1:
            raise ValueError("SR retry_budget must be a positive integer")
        result = classify_sr(
            successes=sr["successes"],
            episodes=sr["episodes"],
            production_equivalent=sr["production_equivalent"],
            budget_enforced=sr["budget_enforced"],
            independent=sr["independent"],
        )
        for key, calculated in (
            ("lower_bound", result.lower_bound),
            ("upper_bound", result.upper_bound),
        ):
            supplied = sr[key]
            if (
                isinstance(supplied, bool)
                or not isinstance(supplied, (int, float))
                or calculated is None
                or abs(float(supplied) - calculated) > 0.0005
            ):
                raise ValueError(f"SR {key} does not match the Wilson calculation")
    elif method == "insufficient-evidence":
        result = SRClassification("X", None, None, "insufficient-evidence")
        required = common | {"method"}
    else:
        raise ValueError(
            "SR evidence method must be deterministic-proof, empirical, "
            "or insufficient-evidence"
        )
    if set(sr) != required:
        raise ValueError("SR evidence fields do not match its selected method")
    if result.value != profile.sr:
        raise ValueError("SR evidence does not support the vector value")


def _check_common_evidence(name: str, entry: Any) -> None:
    if not isinstance(entry, dict):
        raise ValueError(f"{name} evidence must be an object")  # noqa: TRY004 (callers catch ValueError)
    rationale = entry.get("rationale")
    refs = entry.get("evidence_refs")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError(f"{name} evidence rationale must be non-empty")
    if (
        not isinstance(refs, list)
        or not refs
        or any(not isinstance(ref, str) or not ref.strip() for ref in refs)
    ):
        raise ValueError(f"{name} evidence_refs must contain non-empty references")


def validate_untraceability(record: dict[str, Any]) -> str:
    """Validate agent_untraceability evidence and return High, Moderate, Low or X."""
    _check_common_evidence("agent_untraceability", record)
    expected = {"rationale", "evidence_refs", *UNTRACEABILITY_FIELDS}
    if set(record) != expected:
        raise ValueError(
            "agent_untraceability must provide rationale, evidence_refs, and all six "
            "retrieval-exercise observations"
        )
    return classify_untraceability(**{key: record[key] for key in UNTRACEABILITY_FIELDS})


def parse_aivss_vector(vector: str) -> AIProfile:
    """Parse a separate AIVSS:1.0 extension vector (LC/CP/AP/SR/ES)."""
    if not isinstance(vector, str):
        raise ValueError("AIVSS extension vector must be a string")
    parts = vector.strip().split("/")
    if not parts or parts[0] != AIVSS_EXTENSION_PREFIX:
        raise ValueError(
            f"AIVSS extension vector must begin with {AIVSS_EXTENSION_PREFIX!r}"
        )
    keys = [part.partition(":")[0] for part in parts[1:]]
    if any(key in ("EX", "PT", "CA", "TD") for key in keys):
        raise ValueError(
            "This is a legacy eight-metric AIVSS vector (EX, PT, CA, TD). The "
            "AIVSS 1.0 specification uses LC/CP/AP/SR/ES; convert it with "
            "convert_legacy_vector or 'aivss-calc migrate-vector'"
        )
    found: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise ValueError(f"Malformed AIVSS metric segment {part!r}")
        key, _, value = part.partition(":")
        if key in ("EQ", "U"):
            raise ValueError(
                f"AIVSS vector must not carry the derived result {key!r}; report "
                "Effect Class, U and AIVSS as separate fields"
            )
        if key not in AGENTIC_METRICS:
            raise ValueError(f"Unknown AIVSS metric {key!r}")
        if key in found:
            raise ValueError(f"Duplicate AIVSS metric {key!r}")
        expected_index = len(found)
        if (
            expected_index >= len(AGENTIC_METRIC_ORDER)
            or key != AGENTIC_METRIC_ORDER[expected_index]
        ):
            expected = (
                AGENTIC_METRIC_ORDER[expected_index]
                if expected_index < len(AGENTIC_METRIC_ORDER)
                else "end of vector"
            )
            raise ValueError(
                f"AIVSS metric {key!r} is out of order; expected {expected!r}"
            )
        if value not in AGENTIC_METRICS[key]:
            raise ValueError(
                f"Illegal value {value!r} for AIVSS metric {key!r}; "
                f"expected one of {sorted(AGENTIC_METRICS[key])}"
            )
        found[key] = value

    missing = [name for name in AGENTIC_METRIC_ORDER if name not in found]
    if missing:
        raise ValueError(
            "A conformant AIVSS extension vector must specify LC, CP, AP, SR and ES; "
            f"missing: {', '.join(missing)}"
        )
    return AIProfile(**{name.lower(): found[name] for name in AGENTIC_METRIC_ORDER})


def convert_legacy_vector(vector: str) -> dict[str, Any]:
    """Convert a draft eight-metric vector to the five-metric form.

    EX becomes ES. PT and CA are not part of the AIVSS 1.0 specification and
    are dropped. TD maps to agent untraceability metadata.
    """
    parts = vector.strip().split("/")
    if not parts or parts[0] != AIVSS_EXTENSION_PREFIX:
        raise ValueError(
            f"AIVSS extension vector must begin with {AIVSS_EXTENSION_PREFIX!r}"
        )
    found: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep:
            raise ValueError(f"Malformed AIVSS metric segment {part!r}")
        if key not in LEGACY_METRICS:
            raise ValueError(f"Unknown legacy AIVSS metric {key!r}")
        if key in found:
            raise ValueError(f"Duplicate AIVSS metric {key!r}")
        if value not in LEGACY_METRICS[key]:
            raise ValueError(f"Illegal value {value!r} for AIVSS metric {key!r}")
        found[key] = value
    if list(found) != list(LEGACY_METRIC_ORDER):
        raise ValueError(
            "A legacy vector must list LC, CP, AP, SR, EX, PT, CA and TD in order"
        )
    profile = AIProfile(
        lc=found["LC"], cp=found["CP"], ap=found["AP"], sr=found["SR"], es=found["EX"]
    )
    return {
        "aivss_vector": profile.to_vector(),
        "agent_untraceability": UNTRACEABILITY_LABELS[found["TD"]],
        "dropped": {"PT": found["PT"], "CA": found["CA"]},
        "note": (
            "Converted from a draft eight-metric vector: EX is now ES, TD is recorded "
            "as agent_untraceability metadata, and PT and CA are not part of the "
            "AIVSS 1.0 specification."
        ),
    }


_SPLIT_KEYS = set(AGENTIC_METRICS) | set(LEGACY_METRICS)


def split_ai_vector(vector: str) -> tuple[str, AIProfile | None]:
    """Parse display form containing separate CVSS and AIVSS vectors.

    Appending AIVSS metrics inside a CVSS vector is rejected because FIRST's
    Extensions Framework requires extension vectors to be listed separately.
    """
    text = vector.strip()
    if " " in text:
        cvss_vector, aivss_vector = text.split(None, 1)
        return cvss_vector, parse_aivss_vector(aivss_vector)
    for part in text.split("/"):
        key, _, _ = part.partition(":")
        if key in _SPLIT_KEYS:
            raise ValueError(
                f"AIVSS metrics must be in a separate {AIVSS_EXTENSION_PREFIX} "
                "extension vector"
            )
    return text, None
