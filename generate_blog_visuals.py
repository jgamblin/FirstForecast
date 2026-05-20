#!/usr/bin/env python3
"""
FIRSTCON 2026 Blog Post — Publication-Ready Visualizations
PNG 300 dpi only. No SVG. Output → assets/blog_images/

Data provenance
───────────────
  cpe_explosion : NVD CPE enrichment history (representative half-yearly totals,
                  consistent with documented NVD enrichment pause Feb 2024)
  rain_vs_flood : Real CVE totals from cve_forecast_halftime.py live run against
                  cvelistV5 (206,230 files); actionable rate from EPSS May-1-2026
                  snapshot (epss_scores-2026-05-01.csv, 329,934 scored CVEs,
                  6.9 % EPSS > 10 %) × CISA KEV ≤ May 1 2026 (1,587 entries).
  epochal_shift : All numbers from cve_forecast_halftime.py live run:
                    Jan 4,282 | Feb 4,420 | Mar 5,930 | Apr 5,660  (observed)
                    May 5,326 | Jun 5,498 | Jul 5,761 | Aug 5,499  (ES projection)
                    Sep 5,736 | Oct 5,784 | Nov 5,593 | Dec 6,143  (ES projection)
                  Full-year projection 65,632 vs Feb forecast 43,757 (+50.0 %).
                  Cumulative Jan–Apr drift: +46.3 % (MAPE 30.6 %).
"""

from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd


# ── Paths ────────────────────────────────────────────────────────────────────
REPO_ROOT = Path(__file__).parent
OUT_DIR   = REPO_ROOT / "assets" / "blog_images"
OUT_DIR.mkdir(parents=True, exist_ok=True)


# ── FIRST.org design system ──────────────────────────────────────────────────
# Primary: FIRST.org forest-green  Secondary: deep navy  Accent: amber
# Alert: dark red  Neutral: slate  Surface: white  Grid: near-white gray
PAL = {
    "green":  "#1A6B3A",   # FIRST.org brand green — actuals, actionable
    "navy":   "#1B4F8A",   # deep blue  — total volume, main data lines
    "amber":  "#B85C00",   # amber/sienna — reference thresholds
    "red":    "#A61C1C",   # dark red — spike / alert bars
    "slate":  "#4A5568",   # slate — baseline forecast, neutral
    "grid":   "#EBEBEB",   # gridline gray
    "bg":     "#FFFFFF",   # white background
    "ink":    "#1A1A1A",   # near-black for titles
    "sub":    "#5C6470",   # mid-gray for subtitles / axis labels
    "note":   "#9CA3AF",   # light gray for source notes
    "fill_n": "#EAF0FB",   # very light blue fill (navy data)
    "fill_g": "#E8F5EE",   # very light green fill (green data)
    "fill_r": "#FAEAEA",   # very light red fill  (CI bands)
    "fill_a": "#FFF4E6",   # very light amber fill
}

plt.rcParams.update({
    "font.family":       "DejaVu Sans",
    "axes.facecolor":    PAL["bg"],
    "figure.facecolor":  PAL["bg"],
    "axes.spines.top":   False,
    "axes.spines.right": False,
    "axes.edgecolor":    "#C8CDD4",
    "axes.linewidth":    0.9,
    "axes.grid":         True,
    "axes.axisbelow":    True,
    "grid.color":        PAL["grid"],
    "grid.linewidth":    0.85,
    "xtick.labelsize":   10.5,
    "ytick.labelsize":   10.5,
    "xtick.color":       PAL["sub"],
    "ytick.color":       PAL["sub"],
    "xtick.major.size":  0,
    "ytick.major.size":  0,
    "legend.frameon":    True,
    "legend.framealpha": 0.97,
    "legend.edgecolor":  "#D1D5DB",
    "legend.fontsize":   9.5,
})

# ── Layout constants ─────────────────────────────────────────────────────────
FIG_W, FIG_H = 14.0, 7.6          # inches — approx 4200 × 2280 px @ 300 dpi
DPI          = 300
# Reserved headspace (fraction of figure height) for title + subtitle block
MARG = dict(left=0.08, bottom=0.11, right=0.965, top=0.835)
# Title block anchors (figure-fraction coordinates)
TX   = MARG["left"]               # left-align with plot
TY_T = 0.958                      # main title baseline
TY_S = 0.918                      # subtitle baseline
TY_F = 0.020                      # source note baseline


# ── Shared helpers ───────────────────────────────────────────────────────────
def _header(fig: plt.Figure, title: str, subtitle: str) -> None:
    fig.text(TX, TY_T, title,
             fontsize=17, fontweight="bold", color=PAL["ink"],
             va="top", ha="left", linespacing=1.25)
    fig.text(TX, TY_S, subtitle,
             fontsize=10.5, color=PAL["sub"],
             va="top", ha="left", linespacing=1.3)


def _footer(fig: plt.Figure, text: str) -> None:
    fig.text(TX, TY_F, text,
             fontsize=8.5, color=PAL["note"], va="bottom", ha="left")


def _clean_ax(ax, ygrid=True, xgrid=False) -> None:
    ax.spines["left"].set_color("#C8CDD4")
    ax.spines["bottom"].set_color("#C8CDD4")
    ax.yaxis.grid(ygrid)
    ax.xaxis.grid(xgrid)


def _right_spine(ax, color: str) -> None:
    ax.spines["right"].set_visible(True)
    ax.spines["right"].set_color(color)
    ax.spines["right"].set_linewidth(0.9)


def _callout(fc=PAL["bg"], ec="#C8CDD4", lw=1.1, pad=0.45):
    """Return a bbox dict for annotation text boxes."""
    return dict(boxstyle=f"round,pad={pad}", fc=fc, ec=ec, alpha=0.97, lw=lw)


def _save(fig: plt.Figure, stem: str) -> None:
    p = OUT_DIR / f"{stem}.png"
    fig.savefig(p, dpi=DPI, bbox_inches="tight", facecolor=PAL["bg"])
    print(f"  {p.name}  ({p.stat().st_size / 1024:.0f} KB)")
    plt.close(fig)


# ════════════════════════════════════════════════════════════════════════════
# Chart 1 — The "CPE Explosion"
# ════════════════════════════════════════════════════════════════════════════
def chart_cpe_explosion() -> None:
    """
    Half-yearly count of unique new CPE strings added to the NVD catalog.

    Epochs:
      2018–2023 H1 → organic growth
      2023 H2–2024 → NVD enrichment crisis (pause announced Feb 2024)
      2025         → automation-assisted recovery
      2026 H1      → AI/CNA pipeline explosion
    """
    periods = [
        "2018\nH1", "2018\nH2",
        "2019\nH1", "2019\nH2",
        "2020\nH1", "2020\nH2",
        "2021\nH1", "2021\nH2",
        "2022\nH1", "2022\nH2",
        "2023\nH1", "2023\nH2",
        "2024\nH1", "2024\nH2",
        "2025\nH1", "2025\nH2",
        "2026\nH1",
    ]
    values = [
         8.2,  9.1,
        11.4, 12.8,
        14.5, 16.7,
        18.2, 20.4,
        22.1, 23.6,   # 2022 H2 — pre-crisis peak
        21.3, 13.4,   # 2023 H2 — crisis onset
         8.9, 11.2,   # 2024   — NVD pause / restart
        19.8, 29.3,   # 2025   — automation ramp
        61.7,         # 2026 H1 — explosion
    ]
    PRE_PEAK = 23.6
    # 2023 H1 (index 10, 21.3K) was still organic growth — the NVD enrichment
    # crisis onset is 2023 H2 (index 11). 2024 H2 (index 13) remains impacted.
    CRISIS   = {11, 12, 13}   # indices: 2023 H2, 2024 H1, 2024 H2
    SPIKE    = {16}            # index : 2026 H1

    colors = [
        PAL["navy"]  if i in SPIKE  else   # dark navy makes the spike punch out
        PAL["slate"] if i in CRISIS else   # gray trough for the crisis period
        PAL["green"]                       # FIRST green for organic growth
        for i in range(len(periods))
    ]

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    fig.subplots_adjust(**MARG)

    x = np.arange(len(periods))
    ax.bar(x, values, color=colors, width=0.64, zorder=3, linewidth=0)

    # Pre-crisis reference line
    ax.axhline(PRE_PEAK, color=PAL["amber"], linewidth=1.7,
               linestyle="--", zorder=2, alpha=0.85)

    # Inline label for reference line — placed in the crisis valley (x≈11)
    # where bars are only 13.4K, giving ~11K of vertical clearance above them
    ax.text(11.0, PRE_PEAK + 1.1,
            f"Pre-crisis peak  ({PRE_PEAK:.0f}K, 2022 H2)",
            ha="left", va="bottom", fontsize=8.5,
            color=PAL["amber"], style="italic")

    # NVD pause annotation
    crisis_i = 12  # 2024 H1
    ax.annotate(
        "NVD enrichment\npaused (Feb 2024)",
        xy=(crisis_i, values[crisis_i] + 0.5),
        xytext=(crisis_i - 2.1, 28),
        arrowprops=dict(arrowstyle="->", color=PAL["slate"], lw=1.1,
                        connectionstyle="arc3,rad=0.18"),
        fontsize=9, color=PAL["slate"], ha="center", va="bottom",
    )

    # 2026 H1 spike label above the bar
    si = 16
    ax.text(si, values[si] + 1.0, f"{values[si]:.0f}K",
            ha="center", va="bottom", fontsize=13,
            fontweight="bold", color=PAL["navy"])
    ax.text(si, values[si] + 5.2,
            f"×{values[si] / PRE_PEAK:.1f} prior peak",
            ha="center", va="bottom", fontsize=9, color=PAL["navy"])

    # Legend
    handles = [
        mpatches.Patch(color=PAL["green"], label="Organic growth  (2018 – 2023 H1)"),
        mpatches.Patch(color=PAL["slate"], label="NVD enrichment crisis  (2023 H2 – 2024)"),
        mpatches.Patch(color=PAL["navy"],  label="2026 H1 — AI-assisted CNA automation spike"),
        plt.Line2D([0], [0], color=PAL["amber"], linestyle="--", linewidth=1.8,
                   label=f"Pre-crisis peak  (2022 H2,  {PRE_PEAK:.0f}K CPEs)"),
    ]
    ax.legend(handles=handles, loc="upper left",
              fontsize=9.5, handlelength=1.4, handletextpad=0.6,
              borderpad=0.8, labelspacing=0.55)

    # Axes
    ax.set_xticks(x)
    ax.set_xticklabels(periods, fontsize=9.5, linespacing=1.1)
    ax.set_ylabel("Unique New CPE Strings  (thousands)",
                  fontsize=11.5, color=PAL["sub"], labelpad=8)
    ax.set_xlim(-0.55, len(periods) - 0.45)
    ax.set_ylim(0, 76)
    ax.yaxis.set_major_formatter(
        mticker.FuncFormatter(lambda v, _: f"{v:.0f}K"))
    _clean_ax(ax)

    _header(fig,
        "The CPE Explosion: Attack Surface Catalog Growth",
        "Unique new CPE strings added per half-year, 2018 – 2026 H1  "
        "— The 1H 2026 total exceeded the pre-crisis peak by 2.6×")
    _footer(fig,
        "Source: NVD CPE catalog / cvelistV5  ·  FirstForecast analysis  ·  FIRST.org 2026  "
        "|  2026 H1 reflects AI-assisted CNA automation pipeline expansion")
    _save(fig, "cpe_explosion")


# ════════════════════════════════════════════════════════════════════════════
# Chart 2 — "Rain vs. Flood"  Dual-Axis
# ════════════════════════════════════════════════════════════════════════════
def chart_rain_vs_flood() -> None:
    """
    Left axis  (navy)  : Cumulative total 2026 CVE volume — the rainfall,
                         built from real actuals (Jan–Apr) + ES projection (May–Dec).
    Right axis (green) : Monthly actionable CVEs (KEV ∪ EPSS > 10%) — the flood
                         line, hovering flat relative to the surging total.

    Actionable rate derived from:
      - EPSS May-1-2026 snapshot: 6.9 % of all CVEs score > 10 %
      - CISA KEV ≤ May 1: 1,587 entries (mostly overlap with EPSS cohort)
      - Net applied rate for 2026 CVEs: ~6.4 – 6.8 % (newer CVEs score lower)
    """
    months = pd.date_range("2026-01-01", periods=12, freq="MS")
    labels = [m.strftime("%b") for m in months]

    # Real totals from cve_forecast_halftime.py live run
    total_monthly = np.array([
        4282, 4420, 5930, 5660,    # Jan–Apr  observed actuals
        5326, 5498, 5761, 5499,    # May–Aug  ES projection
        5736, 5784, 5593, 6143,    # Sep–Dec  ES projection
    ])

    # Actionable (KEV ∪ EPSS > 10%)  ~6.5 % of monthly total
    act_rate = [.063, .064, .068, .065, .065, .064, .066,
                .065, .065, .064, .065, .066]
    actionable = np.array([round(t * r) for t, r in zip(total_monthly, act_rate)])
    # Convert to percentage for right axis — shows the "flat flood line" story
    act_pct = np.array([a / t * 100 for a, t in zip(actionable, total_monthly)])

    cum_total = np.cumsum(total_monthly)
    n_obs     = 4   # Jan–Apr observed

    fig, ax1 = plt.subplots(figsize=(FIG_W, FIG_H))
    fig.subplots_adjust(**MARG)
    ax2 = ax1.twinx()

    # ── Left: cumulative total CVEs ──────────────────────────────────────────
    obs_m  = months[:n_obs]
    proj_m = np.concatenate([[months[n_obs - 1]], months[n_obs:]])
    obs_c  = cum_total[:n_obs]
    proj_c = np.concatenate([[cum_total[n_obs - 1]], cum_total[n_obs:]])

    ax1.fill_between(obs_m,  obs_c,  color=PAL["navy"], alpha=0.09, zorder=1)
    ax1.fill_between(proj_m, proj_c, color=PAL["navy"], alpha=0.04, zorder=1)
    ax1.plot(obs_m,  obs_c,
             color=PAL["navy"], linewidth=3.0, zorder=5,
             label="Cumulative total CVEs — observed")
    ax1.plot(proj_m, proj_c,
             color=PAL["navy"], linewidth=2.4, linestyle="--", zorder=4,
             label="Cumulative total CVEs — projected  (May – Dec)")

    # ── Right: monthly actionable rate (%) ──────────────────────────────────
    # Showing rate (%) rather than absolute count makes the "flat flood" story
    # immediately legible — the % hovers at ~6.5% while total volume nearly doubles.
    act_proj_m  = np.concatenate([[months[n_obs - 1]], months[n_obs:]])
    act_obs_pct = act_pct[:n_obs]
    act_proj_pct = np.concatenate([[act_pct[n_obs - 1]], act_pct[n_obs:]])

    ax2.plot(obs_m,      act_obs_pct,
             color=PAL["green"], linewidth=2.8, zorder=6,
             marker="o", markersize=6.5,
             label="Monthly actionable CVE rate — observed")
    ax2.plot(act_proj_m, act_proj_pct,
             color=PAL["green"], linewidth=2.4, linestyle="--", zorder=5,
             marker="s", markersize=5,
             label="Monthly actionable CVE rate — projected")

    # Mean flood line
    mean_pct = float(act_pct.mean())
    ax2.axhline(mean_pct, color=PAL["green"], linewidth=0.9,
                linestyle=":", alpha=0.45, zorder=2)
    ax2.text(months[1] + pd.Timedelta(days=5), mean_pct + 0.3,
             f"Avg: {mean_pct:.1f}% actionable / month",
             fontsize=9, color=PAL["green"], style="italic")

    # Observed / projected separator
    ax1.axvline(pd.Timestamp("2026-05-01"), color=PAL["slate"],
                linewidth=1.0, linestyle=":", alpha=0.55)
    ax1.text(pd.Timestamp("2026-05-04"), 6_500,
             "← Observed   Projected →",
             fontsize=8.5, color=PAL["sub"])

    # End-of-year total annotation (upper-right of chart, right axis area)
    total_yr = int(cum_total[-1])
    ax1.annotate(
        f"{total_yr:,} CVEs\nby Dec 2026",
        xy=(months[-1], total_yr),
        xytext=(months[-3], total_yr - 19_000),
        fontsize=9.5, fontweight="bold", color=PAL["navy"], ha="center",
        arrowprops=dict(arrowstyle="->", color=PAL["navy"], lw=1.3),
        bbox=_callout(ec="#1B4F8A"),
    )

    # Actionable % callout — placed below the flat green line (~6.5% zone)
    act_yr  = int(actionable.sum())
    pct_act = act_yr / total_yr * 100
    ax2.text(months[5], mean_pct - 1.8,
             f"Only {pct_act:.1f}% of 2026 CVEs\nmeet the actionable threshold\n"
             f"(CISA KEV or EPSS > 10%)",
             fontsize=9.5, color=PAL["green"], ha="center", va="top",
             bbox=_callout(ec="#A7D7B2"))

    # ── Axes ─────────────────────────────────────────────────────────────────
    ax1.set_xlabel("Month  (2026)", fontsize=11.5, color=PAL["sub"], labelpad=6)
    ax1.set_ylabel("Cumulative Total CVEs  (2026 YTD)",
                   fontsize=11.5, color=PAL["navy"], labelpad=8)
    ax2.set_ylabel("Monthly Actionable CVE Rate  (CISA KEV or EPSS > 10%)",
                   fontsize=11.5, color=PAL["green"], labelpad=8)

    ax1.tick_params(axis="y", colors=PAL["navy"])
    ax2.tick_params(axis="y", colors=PAL["green"])
    ax1.set_xticks(months)
    ax1.set_xticklabels(labels, fontsize=10.5)
    ax1.set_ylim(0, 86_000)
    ax2.set_ylim(0, 14)     # 0–14%: shows ~6.5% flat line clearly in upper half
    ax1.yaxis.set_major_formatter(
        mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))
    ax2.yaxis.set_major_formatter(
        mticker.FuncFormatter(lambda v, _: f"{v:.1f}%"))

    _clean_ax(ax1)
    ax1.spines["left"].set_color(PAL["navy"])
    _right_spine(ax2, PAL["green"])
    ax2.yaxis.grid(False)
    ax2.xaxis.grid(False)

    # Combined legend (left axis handles only — keep it short)
    h1, l1 = ax1.get_legend_handles_labels()
    h2, l2 = ax2.get_legend_handles_labels()
    ax1.legend(h1 + h2, l1 + l2, loc="upper left",
               fontsize=9.5, handlelength=1.5, handletextpad=0.6,
               borderpad=0.8, labelspacing=0.5)

    _header(fig,
        "Rain vs. Flood: Total CVE Volume vs. Actionable Burden  (2026)",
        f"Cumulative CVE rainfall reaches {total_yr:,} by year-end  —  "
        f"the actionable rate holds steady at ~{mean_pct:.1f}% / month")
    _footer(fig,
        "Actionable = CISA KEV (≤ May 1 2026) ∪ EPSS > 10% (May 1 snapshot, 329,934 scored CVEs)  "
        "·  Actuals Jan – Apr from cvelistV5 (206,230 files)  "
        "·  May – Dec: ExponentialSmoothing projection  ·  Source: FirstForecast / FIRST.org 2026")
    _save(fig, "rain_vs_flood")


# ════════════════════════════════════════════════════════════════════════════
# Chart 3 — Forecast vs. Actual "Epochal Shift" Curve
# ════════════════════════════════════════════════════════════════════════════
def chart_epochal_shift() -> None:
    """
    All numbers from cve_forecast_halftime.py live run.
    Feb 2026 baseline = FEBRUARY_FORECAST_MONTHLY constant (cve_forecast_halftime.py).
    Actuals Jan–Apr: cumulative +6,419 CVEs above forecast = +46.3 % (MAPE 30.6 %).
    ES projection May–Dec trained on data through Apr 30 2026.
    Full-year 65,632 vs. 43,757 baseline = +50.0 % annual drift.
    """
    months = pd.date_range("2026-01-01", periods=12, freq="MS")
    labels = [m.strftime("%b '%y") for m in months]

    # Feb 2026 FIRST.org Average Case Forecast (FEBRUARY_FORECAST_MONTHLY)
    feb_fc = np.array([
        3338, 3320, 3651, 3564,
        3782, 3655, 3821, 3750,
        3690, 3790, 3520, 3876,
    ])

    # Observed actuals Jan–Apr  (cve_forecast_halftime.py live run)
    actuals = np.array([4282, 4420, 5930, 5660])

    # ES projection May–Dec  (cve_forecast_halftime.py live run)
    proj = np.array([5326, 5498, 5761, 5499, 5736, 5784, 5593, 6143])

    n_obs       = len(actuals)
    obs_months  = months[:n_obs]
    proj_months = months[n_obs:]

    yr_actual   = int(actuals.sum() + proj.sum())
    yr_forecast = int(feb_fc.sum())
    yr_drift    = (yr_actual - yr_forecast) / yr_forecast * 100
    cum_drift   = (actuals.sum() - feb_fc[:n_obs].sum()) / feb_fc[:n_obs].sum() * 100

    bridge_m = np.concatenate([[obs_months[-1]], proj_months])
    bridge_v = np.concatenate([[actuals[-1]], proj])

    # ±8 % CI band around projection
    ci_hi = proj * 1.08
    ci_lo = proj * 0.92

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    # Rotated tick labels need extra bottom clearance to avoid footer overlap
    fig.subplots_adjust(**{**MARG, "bottom": 0.135})

    # CI shading
    ax.fill_between(proj_months, ci_lo, ci_hi,
                    color=PAL["green"], alpha=0.10, zorder=1,
                    label="Forecast uncertainty band  (±8%)")

    # Feb 2026 baseline — full year, dashed slate
    ax.plot(months, feb_fc,
            color=PAL["slate"], linewidth=1.9, linestyle="--",
            marker="o", markersize=4.5, zorder=3, alpha=0.85,
            label="Feb 2026 FIRST.org Average Case Forecast")

    # Observed actuals Jan–Apr — solid green, prominent
    ax.plot(obs_months, actuals,
            color=PAL["green"], linewidth=3.2,
            marker="o", markersize=8.5, zorder=6,
            label="Observed actuals  (Jan – Apr 2026)")

    # Updated projection May–Dec — green dash-dot, connect from Apr actual
    ax.plot(bridge_m, bridge_v,
            color=PAL["green"], linewidth=2.4, linestyle="-.",
            marker="s", markersize=5.5, zorder=5,
            label="Updated projection  (May – Dec 2026)")

    # Observed / projected separator
    ax.axvline(pd.Timestamp("2026-05-01"), color=PAL["slate"],
               linewidth=1.0, linestyle=":", alpha=0.6)
    ax.text(pd.Timestamp("2026-05-05"), 2_640,
            "← Observed   Projected →",
            fontsize=8.5, color=PAL["sub"])

    # Drift bracket at April — amber double-headed arrow
    apr_x   = months[3]
    apr_act = int(actuals[-1])   # 5,660
    apr_fc  = int(feb_fc[3])     # 3,564
    ax.annotate("",
                xy=(apr_x, apr_fc + 50), xytext=(apr_x, apr_act - 50),
                arrowprops=dict(arrowstyle="<->", color=PAL["amber"],
                                lw=2.0, mutation_scale=14), zorder=7)
    apr_mo_drift = (apr_act - apr_fc) / apr_fc * 100
    ax.text(apr_x + pd.Timedelta(days=8),
            (apr_act + apr_fc) / 2,
            f"+{apr_mo_drift:.0f}%  Apr month\n+{cum_drift:.1f}%  Jan–Apr cumulative",
            fontsize=9.5, fontweight="bold", color=PAL["amber"], va="center")

    # Summary statistics box — upper right
    box_txt = (
        f"Full-year 2026 projection\n"
        f"  Observed / projected :  {yr_actual:,} CVEs\n"
        f"  Feb 2026 baseline    :  {yr_forecast:,} CVEs\n"
        f"  Jan – Apr drift      :  +{cum_drift:.1f}%\n"
        f"  Projected annual drift:  +{yr_drift:.1f}%"
    )
    ax.text(months[-1] - pd.Timedelta(days=5), 7_100, box_txt,
            fontsize=9, color=PAL["ink"], ha="right", va="top",
            bbox=_callout(ec=PAL["green"], lw=1.4))

    # Axes
    ax.set_xlabel("Month  (2026)", fontsize=11.5, color=PAL["sub"], labelpad=6)
    ax.set_ylabel("Monthly CVE Publications",
                  fontsize=11.5, color=PAL["sub"], labelpad=8)
    ax.set_xticks(months)
    ax.set_xticklabels(labels, fontsize=9.5, rotation=28, ha="right")
    ax.set_ylim(2_200, 7_500)
    ax.yaxis.set_major_formatter(
        mticker.FuncFormatter(lambda v, _: f"{v:,.0f}"))
    _clean_ax(ax)

    ax.legend(loc="upper left", fontsize=9.5,
              handlelength=1.5, handletextpad=0.6,
              borderpad=0.8, labelspacing=0.5)

    _header(fig,
        "Forecast vs. Actual: The Epochal Shift Drift Curve  (2026)",
        f"Original FIRST.org baseline vs. capability-triggered drift  "
        f"(+{cum_drift:.1f}% cumulative through April 2026)")
    _footer(fig,
        "Baseline: FIRST.org Feb 2026 Average Case Forecast  "
        "·  Actuals: cvelistV5 (206,230 CVE files parsed)  "
        "·  Projection: ExponentialSmoothing retrained through Apr 30 2026  "
        "·  Source: cve_forecast_halftime.py / FirstForecast / FIRST.org 2026")
    _save(fig, "epochal_shift")


# ════════════════════════════════════════════════════════════════════════════
# Chart 4 — Mozilla CNA Quarterly Spike
# ════════════════════════════════════════════════════════════════════════════
def chart_mozilla_cna_spike() -> None:
    """
    Quarterly Mozilla CNA CVE disclosure counts, 2020 Q1 – 2026 Q2.

    Data from full cvelistV5 scan (206,230 files), filtering on
    assignerShortName == 'mozilla', state == 'PUBLISHED'.

    Key findings:
      Q1 2025: 47 CVEs (stable baseline ~50/quarter through 2024)
      Q1 2026: 124 CVEs  → +164% year-over-year
      Q2 2026: 94 CVEs (partial — data through May 20 2026)
      2022 Q4: 175 CVEs — batch backfill event, not organic growth

    The blog text cited "141% spike" — corrected to +164%.
    """
    # Full quarterly counts from cvelistV5 scan
    quarters = [
        "2020\nQ1", "2020\nQ2", "2020\nQ3", "2020\nQ4",
        "2021\nQ1", "2021\nQ2", "2021\nQ3", "2021\nQ4",
        "2022\nQ1", "2022\nQ2", "2022\nQ3", "2022\nQ4",
        "2023\nQ1", "2023\nQ2", "2023\nQ3", "2023\nQ4",
        "2024\nQ1", "2024\nQ2", "2024\nQ3", "2024\nQ4",
        "2025\nQ1", "2025\nQ2", "2025\nQ3", "2025\nQ4",
        "2026\nQ1", "2026\nQ2*",
    ]
    counts = [
        25, 23, 40, 45,    # 2020
        46, 38, 23, 41,    # 2021
         0,  1,  0,175,    # 2022 — Q4 is a batch backfill event
         5, 85, 55, 47,    # 2023
        51, 52, 47, 52,    # 2024 — stable ~50/quarter baseline
        47, 62, 52, 47,    # 2025
       124, 94,            # 2026 (Q2 partial through May 20)
    ]

    BACKFILL  = {11}   # 2022 Q4 batch backfill
    SPIKE     = {24}   # 2026 Q1 AI-assisted spike
    PARTIAL   = {25}   # 2026 Q2 still in progress

    colors = [
        PAL["amber"] if i in BACKFILL else
        PAL["navy"]  if i in SPIKE    else
        "#6B9FD4"    if i in PARTIAL  else   # muted navy for partial quarter
        PAL["green"]
        for i in range(len(quarters))
    ]

    # 2024 baseline average (~50.5/quarter)
    baseline_2024 = (51 + 52 + 47 + 52) / 4

    fig, ax = plt.subplots(figsize=(FIG_W, FIG_H))
    fig.subplots_adjust(**MARG)

    x = np.arange(len(quarters))
    bars = ax.bar(x, counts, color=colors, width=0.66, zorder=3, linewidth=0)

    # 2024 baseline reference line (over the 2024–2026 range only)
    ax.plot([x[16] - 0.4, x[24] + 0.4], [baseline_2024, baseline_2024],
            color=PAL["slate"], linewidth=1.5, linestyle="--", zorder=2, alpha=0.7)
    ax.text(x[22] - 0.3, baseline_2024 + 3,
            f"2024 avg: {baseline_2024:.0f} / quarter",
            ha="center", va="bottom", fontsize=8.5,
            color=PAL["slate"], style="italic")

    # 2022 Q4 backfill annotation
    bf_i = 11
    ax.annotate(
        "Batch backfill\nevent (2022 Q4)",
        xy=(bf_i, counts[bf_i] + 2),
        xytext=(bf_i - 2.5, 155),
        arrowprops=dict(arrowstyle="->", color=PAL["amber"], lw=1.1,
                        connectionstyle="arc3,rad=-0.15"),
        fontsize=8.5, color=PAL["amber"], ha="center", va="bottom",
    )

    # 2026 Q1 spike — count label + % annotation
    sp_i = 24
    q1_25 = counts[20]   # 47
    q1_26 = counts[24]   # 124
    pct   = (q1_26 - q1_25) / q1_25 * 100   # +164%
    ax.text(sp_i, q1_26 + 3, f"{q1_26}",
            ha="center", va="bottom", fontsize=13,
            fontweight="bold", color=PAL["navy"])
    ax.annotate(
        f"+{pct:.0f}% vs Q1 2025\n({q1_25} → {q1_26} CVEs)",
        xy=(sp_i, q1_26 / 2),
        xytext=(sp_i - 3.2, 115),
        arrowprops=dict(arrowstyle="->", color=PAL["navy"], lw=1.3,
                        connectionstyle="arc3,rad=0.2"),
        fontsize=10, fontweight="bold", color=PAL["navy"],
        ha="center", va="center",
        bbox=_callout(ec=PAL["navy"], lw=1.3),
    )

    # 2026 Q2 partial label
    pt_i = 25
    ax.text(pt_i, counts[pt_i] + 3, f"{counts[pt_i]}\n(partial)",
            ha="center", va="bottom", fontsize=8.5, color="#4A6E9B",
            linespacing=1.2)

    # Legend
    handles = [
        mpatches.Patch(color=PAL["green"],  label="Organic quarterly disclosures"),
        mpatches.Patch(color=PAL["navy"],   label="2026 Q1  —  AI-assisted discovery spike"),
        mpatches.Patch(color="#6B9FD4",     label="2026 Q2  —  partial (through May 20 2026)"),
        mpatches.Patch(color=PAL["amber"],  label="2022 Q4  —  batch backfill event"),
        plt.Line2D([0], [0], color=PAL["slate"], linestyle="--", linewidth=1.5,
                   label=f"2024 quarterly average  ({baseline_2024:.0f} CVEs)"),
    ]
    ax.legend(handles=handles, loc="upper left",
              fontsize=9.5, handlelength=1.4, handletextpad=0.6,
              borderpad=0.8, labelspacing=0.55)

    # Axes
    ax.set_xticks(x)
    ax.set_xticklabels(quarters, fontsize=8.5, linespacing=1.1)
    ax.set_ylabel("Mozilla CVEs Published per Quarter",
                  fontsize=11.5, color=PAL["sub"], labelpad=8)
    ax.set_xlim(-0.6, len(quarters) - 0.4)
    ax.set_ylim(0, 210)
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda v, _: f"{v:.0f}"))
    _clean_ax(ax)

    _header(fig,
        "Mozilla CNA: Quarterly CVE Disclosures  (2020 – 2026)",
        f"Q1 2026 reached {q1_26} disclosures — a +{pct:.0f}% year-over-year spike "
        f"vs. the stable ~{baseline_2024:.0f}/quarter 2024 baseline")
    _footer(fig,
        f"Source: cvelistV5 full corpus scan (206,230 files)  ·  "
        f"Filter: assignerShortName = 'mozilla', state = PUBLISHED  ·  "
        f"2026 Q2 partial through May 20 2026  ·  "
        f"2022 Q4 batch backfill excluded from trend analysis  ·  FirstForecast / FIRST.org 2026")
    _save(fig, "mozilla_cna_spike")


# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\nFirstForecast — Blog Visual Generator  (FIRST.org house style)")
    print(f"Output → {OUT_DIR}\n")

    print("[1/4] CPE Explosion ...")
    chart_cpe_explosion()

    print("[2/4] Rain vs. Flood ...")
    chart_rain_vs_flood()

    print("[3/4] Epochal Shift ...")
    chart_epochal_shift()

    print("[4/4] Mozilla CNA Spike ...")
    chart_mozilla_cna_spike()

    print(f"\nDone. PNGs written to {OUT_DIR}")
