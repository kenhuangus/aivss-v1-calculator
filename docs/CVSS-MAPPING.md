# CVSS v4.0 and AIVSS Boundaries

AIVSS uses the
[CVSS v4.0 Extensions Framework](https://www.first.org/cvss/v4.0/user-guide)
(User Guide, Section 3.11). The CVSS vector and AIVSS extension vector are
listed separately, the AIVSS vector on its own line after the CVSS vector:

```text
CVSS:4.0/AV:.../SA:...
AIVSS:1.0/LC:.../CP:.../AP:.../SR:.../ES:...
```

AIVSS does not add metrics to a CVSS metric group or change CVSS definitions,
formulas, constants, ordering, or scores. CVSS-BTE is always published beside
AIVSS. Derived results (Effect Class, U and AIVSS) are report fields, never
vector entries.

## Non-overlap rule

If a property is representable in any CVSS Base, Threat or Environmental metric
that participates in CVSS-BTE, score it there. An agentic metric may record
only properties that are unique to agentic AI control paths and not named by
those CVSS metrics. SR is the one declared exception: it refines AT.

## Separation rules

| AIVSS metric | Related CVSS or CISA concept | Boundary |
|---|---|---|
| LC | CVSS UI | UI records required human participation. LC records how attacker-controlled language reaches security-relevant agent logic. |
| CP | No direct CVSS equivalent | CP records behavioral persistence of attacker-controlled context or memory, not data-retention policy in general. Integrity or confidentiality impact of poisoned memory stays in CVSS. |
| AP | CVSS SC/SI/SA | AP records whether intent or authority crosses a trust boundary into another agent, tenant, principal or policy domain. SC/SI/SA record the resulting impact to subsequent systems. |
| SR | CVSS AT; CVSS E; CISA Automatable | SR records the measured reliability of the language-controlled path under the production retry budget and must agree with AT: SR:P or SR:U requires AT:P. E records exploit maturity and Automatable asks whether all exploitation steps can be automated. Neither may be inferred from SR. |
| ES | CVSS AV/PR/AT and SC/SI/SA | ES records whether reachable tool, MCP, skill or plugin identity, operations, arguments and credentials are independently constrained. CVSS records reach, prerequisites, and realized impact. |

## Properties CVSS already owns

| Property | CVSS home |
|---|---|
| Tool or API blast radius and downstream CIA loss | SC, SI, SA (and VC/VI/VA on the agent) |
| Attacker prerequisite privilege or stolen agent credential as entry condition | PR |
| Required human approval or click | UI |
| Network, local or physical reachability | AV |
| Built-in conditions the attacker must overcome, such as a guardrail to evade | AC |
| Execution conditions, including success that needs repeated attempts | AT |
| Public exploit, KEV or observed attacks | E |
| Service denial, degradation, token or CPU exhaustion that denies service | VA, SA |
| Unauthorized modification, including repudiation from insufficient classical logging | VI, SI |

None of these may be recorded in an agentic metric or reflected in U.

## Double-counting controls

1. CVSS records realized technical impact. AIVSS metrics record path properties;
   do not increase CVSS impact values merely because an AIVSS value is severe.
2. ES does not participate in the Agentic Effect Class; it enters only the
   informative Lookup Table U.
3. Agent untraceability is metadata. Classical missing-log repudiation stays in
   CVSS VI/SI.
4. The decision track never derives CISA Automatable from SR or Technical
   Impact from CVSS impact metrics.
5. Each report covers one coherent exploit path. Combining metric maxima from
   unrelated paths can create a profile that no attacker can realize.

## Scope limits

The five metrics are not a claim to cover all AI, safety, privacy, legal, or
business risk. They describe the Agentic AI exploit-path properties selected
for this specification. Examples outside the profile include model bias,
general accuracy, regulatory jurisdiction, business criticality, safety cases,
training-data governance unrelated to the path, and portfolio-level risk
appetite.

OWASP ASI categories classify finding type. They are not score multipliers.
Organization context belongs outside portable technical severity.
