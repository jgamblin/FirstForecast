# CVE 2026 Half-Year Forecast Update

**How It's Going:** Comparing the [February 2026 FIRST.org Vulnerability Forecast](https://www.first.org/blog/20260211-vulnerability-forecast-2026) against actual CVE publication data (January–April 2026).

## Live Report

**[View the full report →](https://jgamblin.github.io/FirstForecast/)**

## Key Findings

| Metric                     | Value                      |
| -------------------------- | -------------------------- |
| Cumulative drift (Jan–Apr) | **+46.3%** above forecast  |
| MAPE                       | **30.6%**                  |
| Excess CVEs vs. forecast   | **+6,420**                 |
| Revised 2026 projection    | **~68K** (80% CI: 55K–80K) |

### What's Driving the Overshoot

- **GitHub Security Advisories (GHSA):** +449% YoY — expanded curation team + CVE ID backfill campaign
- **VulnCheck (CNA of Last Resort):** +3,119% YoY — absorbing unassigned vulnerability backlog
- **AI-Assisted Discovery:** Mozilla +141% YoY, driven by Anthropic's Project Glasswing (Claude Opus 4.6 and Mythos Preview autonomously finding Firefox bugs)

### What's Declining

- **Patchstack:** −43% — reduced WordPress plugin disclosure volume
- **MITRE:** −29% — product-specific CNAs now assign their own IDs
- **@huntr_ai:** −91% — apparent operational pause

## Methodology

- **Data source:** [CVE Program cvelistV5](https://github.com/CVEProject/cvelistV5) (local mirror, ~200K records parsed)
- **Model:** AutoARIMA via [Darts](https://github.com/unit8co/darts) framework, trained on daily publication counts 2020–2026
- **Ingestion:** Multi-process parallel JSON parsing (~15s for 200K files)
- **Outlier detection:** Z-score on daily counts (Jan–Apr 2026 window)

## Running Locally

```bash
pip install darts pandas tqdm
python cve_forecast_halftime.py
```

Requires a local clone of cvelistV5 at `~/data/cvelistV5/`.

## References

- [FIRST.org: 2026 Vulnerability Forecast (Feb 11, 2026)](https://www.first.org/blog/20260211-vulnerability-forecast-2026)
- [Anthropic Red Team: Assessing Claude Mythos Preview](https://red.anthropic.com/2026/mythos-preview/)
- [VulnCheck: Tracking CVEs Attributed to Anthropic (Project Glasswing)](https://www.vulncheck.com/blog/anthropic-glasswing-cves)

## License

Apache 2.0
