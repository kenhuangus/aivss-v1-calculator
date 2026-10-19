# Specification figures

Figures 1 to 6 of the AIVSS 1.0 condensed specification. Each PNG is rendered
from the HTML source in `src/` (shared styles in `src/_base.css`, connector
drawing in `src/_wires.js`) at 760 CSS px wide and 2x device scale.

| File | Figure |
| --- | --- |
| fig1-pipeline.png | Figure 1: AIVSS scoring pipeline |
| fig2-lookup.png | Figure 2: Lookup Table AIVSS with a worked lookup |
| fig3-taxonomy.png | Figure 3: Core Risks, ASI Top 10, MAESTRO and AIVSS scoring |
| fig4-boundary.png | Figure 4: Boundary between CVSS metrics and agentic metrics |
| fig5-evidence-ssvc.png | Figure 5: Exploitation evidence, severity and SSVC timeline |
| fig6-checklist.png | Figure 6: Assessor checklist |

To re-render after editing a source file:

```bash
pip install playwright && playwright install chromium
python scripts/render_figures.py
```
