# AIVSS 1.0

## 🌐 Try it online

Two live resources are hosted for this project — no installation needed:

1. **Interactive Web Calculator** — score an agentic AI vulnerability in your
   browser. Pick the CVSS v4.0 and Agentic AI metrics or start from one of the
   ten OWASP Agentic Top 10 examples, and get CVSS-BTE, the Agentic Effect
   Class, Agentic Uplift U, the AIVSS lookup score, and an optional SSVC /
   CISA BOD 26-04 remediation timeline instantly.
   It runs the exact same reference code as the CLI.
   **→ https://kenhuangus.github.io/aivss-v1-candidate/**

2. **Interactive Slide Deck** — a 23-slide masterclass presentation covering
   the AIVSS 1.0 decoupled architecture, CVSS v4.0 interpretation, SSVC / BOD
   26-04 timelines, and the EchoLeak (`CVE-2025-32711`) case study. Use arrow
   keys to navigate. The deck predates the AIVSS 1.0 specification and still
   shows the draft eight-metric profile; the specification and this README
   are authoritative.
   **→ https://kenhuangus.github.io/aivss-v1-candidate/slides.html**

AIVSS is a CVSS v4.0 extension for rating the cybersecurity severity of
vulnerabilities in Agentic AI systems. It keeps the official CVSS v4.0 vector
and score intact, records five categorical Agentic AI metrics in a separate
extension vector, and reads the AIVSS score from published lookup tables. No
arithmetic is performed on the agentic metrics.

Status: **candidate**. The metric rubric, lookup tables and conformance rules
are testable. The Table 6 cell values are policy settings that have not yet
been validated against independently rated findings, and the remediation
overlay and organization-local priority index are **not empirically
calibrated**; none of them may be presented as probabilities or regulatory
requirements.
The [extension manifest](aivss-extension.json) records
`first_validation_status: not-submitted`; FIRST has not validated or endorsed
this candidate.

## Model

Every assessment publishes four results for one exploit path:

1. **CVSS-BTE**: the unmodified FIRST CVSS v4.0 score, labelled with the FIRST
   nomenclature for the groups assessed (for example CVSS-BT)
2. **Agentic Effect Class**: A0, A1, A2 or AX from an ordered rule ladder on
   LC, CP, AP and RH
3. **Agentic Uplift U**: an informative 0–10 ordinal from Lookup Table U
   (Effect Class, RH within A2, and ES)
4. **AIVSS**: the final score from Lookup Table AIVSS, keyed by the CVSS-BTE
   band and the Effect Class. A0 and AX keep CVSS-BTE; A1 and A2 take the
   higher of the table cell and CVSS-BTE, so AIVSS is never lower than CVSS-BTE

| CVSS band | A0 or AX | A1 | A2 |
|---|---|---|---|
| None | 0.0 | 0.0 | 0.0 |
| Low | CVSS-BTE | 5.5 | 7.1 |
| Medium | CVSS-BTE | 7.5 | 8.9 |
| High | CVSS-BTE | 8.7 | 9.5 |
| Critical | CVSS-BTE | 9.7 | 10.0 |

- Classifying metrics: **LC, CP, AP, RH**; uplift metric: **ES**
- Unknown evidence value: **X**; any X on LC, CP, AP or RH makes the result
  `provisional`
- **RH (reward hacking)** records whether the agent's own optimization of a proxy objective, evaluator or verifier drives it across a security boundary; CVSS v4.0 has no equivalent metric
- **Agent untraceability** (High, Moderate, Low or X) is mandatory report
  metadata from a retrieval exercise; it is not part of the vector or the score
- **Exploit Maturity (`E`):** resolved from the evidence ladder before CVSS-BTE scoring
- **Taxonomy:** ASI01–ASI10, or `MAESTRO-EXTENDED` with layer/threat metadata
- **Conformance Level 1** is the scored report; **Conformance Level 2** adds the
  SSVC / BOD 26-04 decision track

Conformance Level 2 uses CERT/CC SSVC decision table **`cisa:DT_BOD2604:1.0.0`**
(BOD 26-04), with Agentic Effect Class **A2** advancing the recommended
timeline one tier.

CVSS and AIVSS vectors are separate, following the
[CVSS v4.0 Extensions Framework](https://www.first.org/cvss/v4.0/user-guide):

```text
CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:H/SI:N/SA:N/E:P
AIVSS:1.0/LC:D/CP:C/AP:L/RH:D/ES:W
```

This ASI06 reference path reports CVSS-BT 7.8 (High), Effect Class A2 (AP:L),
U 10 and AIVSS 9.5.

## Reference calculator conformance

Repository: https://github.com/kenhuangus/aivss-v1-candidate

The reference calculator (`aivss-calc` 1.2.0) implements the AIVSS 1.0
specification at Conformance Levels 1 and 2:

1. Resolves Exploit Maturity (`E`) from the evidence ladder before severity
2. Requires a complete five-metric Agentic AI Profile and an agent
   untraceability record for every assessment, and validates the RH evidence
3. Derives the Effect Class, U and AIVSS from the ladder and Tables 5 and 6
4. Accepts ASI01–ASI10 and MAESTRO-extended taxonomy metadata
5. Emits SSVC/BOD decision tracks at Conformance Level 2

Draft eight-metric vectors (`.../EX:W/PT:H/CA:M/TD:H`) are rejected by the
parser. Convert them with `aivss-calc migrate-vector`: EX becomes ES, TD
becomes agent untraceability, and PT and CA are dropped.

The `legacy` subcommand reproduces withdrawn v0.x uplift scores for migration
comparison only and must not be used for AIVSS 1.0 compliance.

## Install and verify

```bash
pip install -e ".[dev]"
pytest   # full suite
aivss-calc verify
```

The in-browser calculator has its own end-to-end tests. They need Playwright, a
Chromium browser, and network access, so they are skipped unless explicitly
enabled:

```bash
pip install -e ".[dev,browser]"
playwright install chromium
AIVSS_BROWSER_TESTS=1 pytest tests/test_web_calculator_browser.py
```

## CLI

```bash
aivss-calc assess examples/asi06-example.json
aivss-calc profile "CVSS:4.0/..." --aivss-vector "AIVSS:1.0/LC:D/CP:C/AP:L/RH:D/ES:W"
aivss-calc migrate-vector "AIVSS:1.0/LC:D/CP:C/AP:L/SR:R/EX:W/PT:H/CA:M/TD:H"
aivss-calc rubric
aivss-calc demo
```

## Web calculator

Launch **`aivss-calc demo`** and open http://127.0.0.1:8765/ to score a finding
interactively: pick the CVSS v4.0 and Agentic AI metrics (or paste a vector
pair, including a draft eight-metric vector, which is converted), record agent
untraceability, and the page shows the AIVSS lookup score with its qualitative
rating, CVSS-BTE beside it, the Agentic Effect Class, U, the MacroVector, and,
when enabled, the SSVC / BOD 26-04 remediation timeline with the A2 overlay. The ten OWASP Agentic Top 10
reference scenarios are available as presets, and every result has a shareable
link that carries the vectors.

The page runs this package itself through
[Pyodide](https://pyodide.org/) (`web/engine.js` loads the bundle served at
`py/aivss_calc.zip`), so browser results come from the same code as the CLI and
cannot drift from it. Loading the runtime takes a few seconds on first visit and
needs network access to the Pyodide CDN; the CLI works offline.

Live demo (GitHub Pages): see **[Try it online](#-try-it-online)** at the top of this README.

Regenerate all OWASP ASI reference inputs, the summary, and the full ASI06
report (`examples/asi06-report.json`) from the single scenario catalog:

```bash
python examples/generate_asi_examples.py
```

These are synthetic format and calculation fixtures, not incidents, an
empirical validation corpus, or evidence that the candidate model predicts
outcomes. ASI category names come from the
[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/);
OWASP does not endorse this AIVSS candidate.

## Presentation slides

An interactive 23-slide HTML deck covers the AIVSS 1.0 decoupled architecture,
CVSS v4.0 interpretations, SSVC / CISA BOD 26-04 timelines, and the EchoLeak
(`CVE-2025-32711`) case study. It predates the AIVSS 1.0 specification and
still shows the draft eight-metric profile — see the
**[Try it online](#-try-it-online)** link at the top for the live deck.

- **Live presentation (GitHub Pages):** https://kenhuangus.github.io/aivss-v1-candidate/slides.html
- **Repository source:** [slides.html](slides.html) (mirrored at [docs/slides.html](docs/slides.html))
- **Navigation controls:** Arrow keys or Space to advance, `F` for fullscreen, `M` to toggle Grid View, and `G` to jump to a specific slide.

## Resources

- [Masterclass slides](slides.html): interactive 23-slide deck on architecture, scoring, and remediation ([Live](https://kenhuangus.github.io/aivss-v1-candidate/slides.html))
- [Input schema](schemas/aivss-assessment-input-v1.0.json)
- [Report schema](schemas/aivss-report-v1.0.json)

`aivss_calc/data/cvss_v4_lookup.json` is derived from the FIRST CVSS v4.0
reference implementation under the BSD-2-Clause license; see
[third-party notices](THIRD_PARTY_NOTICES.md). CVSS is owned and managed by
FIRST.Org, Inc. Its use does not imply FIRST endorsement of AIVSS.

## License

AIVSS is an OWASP project. Unless otherwise noted, the contents of this
repository are licensed under the [Apache License, Version 2.0](LICENSE).
Third-party components remain under their own licenses; see
[third-party notices](THIRD_PARTY_NOTICES.md).
