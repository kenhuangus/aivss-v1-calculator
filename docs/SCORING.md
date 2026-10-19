# AIVSS Calculator Algorithms

This document defines calculator behavior for AIVSS 1.0 (condensed
specification), rubric 1.1.0, calculator 1.1.0. Normative metric meanings live
in [METRIC-RUBRIC.md](METRIC-RUBRIC.md). Every step below is a category
assignment, an ordered rule, or a table lookup; no arithmetic is performed on
ordinal agentic levels.

## Four published results

Every assessment publishes, for one exploit path:

1. `cvss_bte`: the official CVSS v4.0 score from the unmodified FIRST algorithm,
   labelled with the FIRST nomenclature for the metric groups assessed
   (`CVSS-B`, `CVSS-BT`, `CVSS-BE` or `CVSS-BTE`).
2. `agentic_effect_class`: A0, A1, A2 or AX from the ordered rule ladder.
3. `agentic_uplift_u`: the informative ordinal U (0 to 10) from Lookup Table U.
4. `aivss`: the final combined severity from Lookup Table AIVSS.

`agent_untraceability` (High, Moderate, Low or X) is reported beside them as
mandatory metadata. It is not part of the vector, U or the score.

## Assessment unit

An assessment represents one finding on one coherent exploit path. Do not take
the worst value of each metric from different paths and combine them. Score
materially different paths separately and retain a stable `path_id`. The
vulnerability-level AIVSS is the highest path AIVSS (comparison only), reported
with that path's CVSS-BTE, Effect Class and U.

All five metrics (LC, CP, AP, SR, ES) are required for every Conformance Level 1
assessment. Use `X` when evidence cannot resolve a metric. The result is
`provisional` whenever any of LC, CP, AP or SR is `X`.

## CVSS result

`cvss_bte` is produced from the separate, valid CVSS v4.0 vector after Exploit
Maturity (`E`) is resolved from the factual evidence ladder. AIVSS does not
modify CVSS metric definitions, constants, ordering, or the official CVSS score
algorithm. Consumers must always retain and display `cvss_bte`.

The reference `assess` path resolves `E` before severity interpolation:

- CISA KEV, Vulnrichment active, or organization-observed exploitation → `E:A`
- Proof-of-concept without an Attacked condition → `E:P`
- Completed ladder with no affirmative evidence → `E:U`
- Explicit unresolved threat intelligence → `E:X`

EPSS may be recorded as dated metadata and never sets `E`, U or AIVSS. Reports
include `cvss.exploit_maturity` with the resolved value, ladder rung, and input
vector.

SR must agree with CVSS Attack Requirements: `SR:P` or `SR:U` requires `AT:P`,
because FIRST's AT:P covers attacks that may need to be launched several times
against one target. The check uses the effective value, so `MAT` overrides `AT`
when it is set. The calculator rejects a vector pair that breaks this rule.

## Agentic Effect Class (ordered rule ladder)

Evaluate top to bottom; the first match wins:

1. `A2`: `AP:L`; or `LC` in {D, I} with `CP:C`; or `LC:D` with `SR:R`.
2. `A1`: otherwise, `LC` in {D, I}, or `CP` in {S, C}, or `AP:C`.
3. `AX`: otherwise, any of LC, CP or AP is `X`.
4. `A0`: otherwise.

An A2 or A1 clause applies when its own metrics are known even if another
classifying metric is `X`, so missing evidence never lowers the class below
what the known evidence supports. `LC:M` alone does not trigger A1, and `SR`
enters only the A2 clause. `ES` does not enter the Effect Class. Reports label
the class `candidate-unvalidated`: its boundaries are explicit and
deterministic, but have not yet passed the gates in
[VALIDATION.md](VALIDATION.md).

## Lookup Table U (Table 5)

Read U from the Effect Class, SR (within A2 only) and ES. AX uses the A0 row.
U is `null` when ES is `X`.

| Effect Class key | ES:N | ES:M | ES:W |
|---|---|---|---|
| A0 (or AX provisional) | 0 | 1 | 2 |
| A1 | 3 | 5 | 6 |
| A2 and SR ≠ R | 7 | 8 | 9 |
| A2 and SR:R | 8 | 9 | 10 |

U is an informative ordinal label. No decision uses it, and it is never added
to CVSS-BTE. Label it "AIVSS U" in reports so it is not confused with the CVSS
Supplemental metric Provider Urgency.

## Lookup Table AIVSS (Table 6)

Key the table on the FIRST qualitative band of CVSS-BTE and the Effect Class.

| CVSS band (FIRST) | A0 or AX (provisional) | A1 | A2 |
|---|---|---|---|
| None (0.0) | 0.0 | 0.0 | 0.0 |
| Low (0.1–3.9) | CVSS-BTE (unchanged) | 5.5 | 7.1 |
| Medium (4.0–6.9) | CVSS-BTE (unchanged) | 7.5 | 8.9 |
| High (7.0–8.9) | CVSS-BTE (unchanged) | 8.7 | 9.5 |
| Critical (9.0–10.0) | CVSS-BTE (unchanged) | 9.7 | 10.0 |

- A0 and AX: `aivss = cvss_bte` (`rule: cvss_bte_unchanged`; AX is provisional).
- A1 and A2: `aivss` is the higher of the cell and `cvss_bte`
  (`rule: cell` when the cell is at least CVSS-BTE, otherwise
  `rule: cvss_bte_floor`).

AIVSS is therefore never lower than CVSS-BTE and stays within 0.0 to 10.0, as
the CVSS v4.0 Extensions Framework (User Guide, Section 3.11) requires of an
extension that changes the score. Cell values are discrete policy settings, not
measurements. Within one cell, order findings by CVSS-BTE (comparison only).

The report's `scores` object carries `cvss_bte`, `cvss_nomenclature`,
`cvss_band`, `agentic_effect_class`, `provisional`, `agentic_uplift_u`, `aivss`,
`aivss_band`, `table_cell`, `rule`, `status` (`normative`) and `basis`.

## Agent untraceability

Record `agent_untraceability` from a documented retrieval exercise on the
deployment. The input carries the rationale, evidence references and six
observations; the calculator derives the value:

- **High:** the exercise cannot reconstruct the ordered security-relevant
  actions on the path or cannot bound the affected principals.
- **Moderate:** both can be reconstructed, but required fields, integrity
  protection of the records, or verified retention is missing.
- **Low:** both can be reconstructed, required fields are complete, the records
  are integrity-protected, and retention is verified.
- **X:** no completed retrieval exercise.

Classical repudiation from missing logs stays in CVSS VI/SI.

## Decision support (Conformance Level 2)

For a CVE, the calculator applies the published CERT/CC SSVC deployer table for
CISA BOD 26-04 (`cisa:DT_BOD2604:1.0.0`) using:

- KEV status
- asset exposure
- Automatable
- Technical Impact

Reports identify the transcribed decision model as `cisa:BOD2604:1.0.0` and
retain links to both the machine-readable
[CERT/CC response model](https://certcc.github.io/SSVC/howto/cisa_response/)
and the CISA directive.

Vulnrichment values take precedence. For a CVE that is not in KEV and for which
CISA has published neither Automatable nor Technical Impact, CISA's
implementation guidance applies the table with Automatable no and Technical
Impact total until values are published: 14 days for a publicly exposed asset
and Fix on System Upgrade otherwise. The report sets
`missing_metadata_faq_applied`. KEV entries must use the metadata CISA
publishes for them; the calculator does not silently default missing KEV data.
Where public exposure is unknown, the asset is treated as internal and the
source records that choice. The result is labelled a compliance result only
when `fceb_bod_2604_scope=true`; otherwise it is labelled informative CVE
guidance because the directive does not apply to every organization or system.

For a non-CVE finding, Automatable and Technical Impact must be supplied
explicitly. The table result is labelled `informative_bod_26_04_analogy`,
`compliance_applicable=false`, and is not a regulatory deadline. AIVSS never
derives these inputs from SR or CVSS.

The overlay advances the recommended timeline one tier (FSU→60D, 60D→14D,
14D→3D) when the Effect Class is `A2`. It never creates a forensic-triage
obligation and never removes one: a CISA `3DF` result remains `3DF`. When the
Effect Class is `AX` the overlay cannot trigger and `overlay_status` is
`provisional`; otherwise it is `experimental-uncalibrated`. Agent
untraceability is recorded in the decision points but never changes the
timeline. The unmodified BOD baseline is always reported beside the AIVSS
recommendation.

See the official
[BOD 26-04 directive](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
and
[implementation guidance](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk).

## Migrating draft eight-metric vectors

Vectors written for the AIVSS 1.0 draft (`LC/CP/AP/SR/EX/PT/CA/TD`) are rejected
by the parser. Convert them with `aivss-calc migrate-vector` (or
`convert_legacy_vector`): EX becomes ES, TD becomes `agent_untraceability`
metadata, and PT and CA, which are not part of the condensed specification,
are dropped and listed in the output. The web calculator converts a pasted
draft vector automatically and shows the migration note. Re-assess
untraceability with a retrieval exercise before publishing; the TD mapping is
a starting point only.

## Organization-local priority

AIVSS-P is retained only as an optional, organization-local, uncalibrated
ordering aid. Its output is not comparable across organizations and is omitted
from public reference examples. Organizations must calibrate its inputs and
bands against their own outcome data before operational use. They must also
define residual likelihood so it does not re-count CVSS Threat, SR, exposure,
or other evidence already present in the assessment.
