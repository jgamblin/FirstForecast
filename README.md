# CVE 2026 Half-Year Forecast Update

> **Correction, 18 November 2026.** The 43,757 baseline in this repository is not a number FIRST published. [FIRST's February forecast](https://www.first.org/blog/20260211-vulnerability-forecast-2026) gave a median of 59,427 CVEs for 2026, with a 90% interval of 30,012 to 117,673. The monthly figures in `FEBRUARY_FORECAST_MONTHLY`, which sum to 43,757, came from this repository and I labelled them as FIRST's. That was my error.
>
> Every comparison below is against that baseline: the +46.3% drift, the 30.6% MAPE, the excess CVEs and the 50% revision. The chart labels carry the same wording. FIRST did not publish a monthly breakdown. Spread evenly across the year, its median comes to 19,809 for January to April, and the 20,293 CVEs published in those months were 2.4% above that.
>
> The revised projection of 65,632 is this model's own output and does not depend on the baseline. The findings below are left as published in May 2026.

**How It's Going:** Comparing the [February 2026 FIRST.org Vulnerability Forecast](https://www.first.org/blog/20260211-vulnerability-forecast-2026) against actual CVE publication data (January–April 2026).

## Live Report

**[View the full report →](https://jgamblin.github.io/FirstForecast/)**

## Key Findings

| Metric                     | Value                      |
| -------------------------- | -------------------------- |
| Cumulative drift (Jan–Apr) | **+46.3%** above forecast  |
| MAPE                       | **30.6%**                  |
| Excess CVEs vs. forecast   | **+6,419**                 |
| Revised 2026 projection    | **65,632** (vs. baseline 43,757) |

### What's Driving the Overshoot

- **GitHub Security Advisories (GHSA):** +449% YoY — expanded curation team + CVE ID backfill campaign
- **VulnCheck (CNA of Last Resort):** +3,119% YoY — absorbing unassigned vulnerability backlog
- **AI-Assisted Discovery:** Mozilla +164% YoY in Q1 (47 → 124 CVEs), driven by Anthropic's Project Glasswing (Claude Opus 4.6 and Mythos Preview autonomously finding Firefox bugs)

### What's Declining

- **Patchstack:** −43% — reduced WordPress plugin disclosure volume
- **MITRE:** −29% — product-specific CNAs now assign their own IDs
- **@huntr_ai:** −91% — apparent operational pause

## Blog Visualizations

Publication-ready charts (300 dpi PNG) for the FIRST.org halftime blog post are in [`assets/blog_images/`](assets/blog_images/):

| File | Description |
| ---- | ----------- |
| `cpe_explosion.png` | NVD CPE catalog growth, 2018–2026 H1 |
| `rain_vs_flood.png` | Total CVE volume vs. actionable burden (6.5% rate) |
| `epochal_shift.png` | Feb 2026 forecast vs. observed actuals + ES projection |
| `mozilla_cna_spike.png` | Mozilla CNA quarterly disclosures, 2024–2026 (+164% Q1 YoY) |

## Methodology

- **Data source:** [CVE Program cvelistV5](https://github.com/CVEProject/cvelistV5) (local mirror, 206,230 records parsed)
- **Actuals:** Jan–Apr 2026 from cvelistV5 (`datePublished`, state=PUBLISHED)
- **Model:** ExponentialSmoothing via [Darts](https://github.com/unit8co/darts), trained on daily publication counts 2020–2026 (AutoARIMA unavailable on Python 3.14 — no `statsforecast` wheel)
- **Exploitability threshold:** CISA KEV (≤ May 1 2026, 1,587 entries) OR EPSS > 10% (May 1 2026 snapshot, 329,934 CVEs scored)
- **Ingestion:** Multi-process parallel JSON parsing (~17s for 206K files)
- **Outlier detection:** Z-score on daily counts (Jan–Apr 2026 window)
- **Data cutoff:** May 1, 2026 for all three datasets (CVE corpus, KEV, EPSS) for reproducibility

## Scripts

| Script | Purpose |
| ------ | ------- |
| `cve_forecast_halftime.py` | Ingest cvelistV5, compare actuals vs. Feb forecast, generate ES projection |
| `exploitability_overlay.py` | GitHub_M + VulnCheck volume vs. actionable burden analysis |
| `generate_blog_visuals.py` | Generate the four 300 dpi PNG charts |

## Running Locally

```bash
pip install u8darts pandas numpy matplotlib tqdm
python cve_forecast_halftime.py
python exploitability_overlay.py
python generate_blog_visuals.py
```

Requires a local clone of cvelistV5 at `~/data/cvelistV5/` and EPSS/KEV snapshots at `~/Data/KEV/`.

## References

- [FIRST.org: 2026 Vulnerability Forecast (Feb 11, 2026)](https://www.first.org/blog/20260211-vulnerability-forecast-2026)
- [Anthropic Red Team: Assessing Claude Mythos Preview](https://red.anthropic.com/2026/mythos-preview/)
- [VulnCheck: Tracking CVEs Attributed to Anthropic (Project Glasswing)](https://www.vulncheck.com/blog/anthropic-glasswing-cves)
- [Mozilla: Hardening Firefox with Claude Mythos Preview](https://hacks.mozilla.org/2026/hardening-firefox-with-claude-mythos-preview/)

## License

Apache 2.0
