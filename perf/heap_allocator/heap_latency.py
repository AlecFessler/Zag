#!/usr/bin/env python3
import os
import math
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

DATA_FILE = "data/heap_latency.csv"
PLOTS_DIR = "plots"
ZOOM_Q = 0.99
ZOOM_BINS = 200

# -----------------------
# I/O + utilities
# -----------------------

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def savefig(path: str, fig=None):
    if fig is None:
        fig = plt.gcf()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)

def read_data(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df['op'] = df['op'].astype(str)
    df['type'] = df['type'].astype(str)

    def parse_bool(x):
        if isinstance(x, str):
            return x.strip().lower() in ('1', 'true', 't', 'yes', 'y')
        return bool(x)

    df['from_tree'] = df['from_tree'].apply(parse_bool)
    df['depth'] = pd.to_numeric(df['depth'], errors='coerce').fillna(-1).astype(int)
    df['size'] = pd.to_numeric(df['size'], errors='coerce')
    df['tree_count'] = pd.to_numeric(df['tree_count'], errors='coerce')
    df['cycles'] = pd.to_numeric(df['cycles'], errors='coerce')
    df['i'] = pd.to_numeric(df['i'], errors='coerce')
    return df

# -----------------------
# Plot helpers
# -----------------------

def scatter(x, y, xlabel, ylabel, title, out_path, xlog=False, ylog=False, alpha=0.3, s=6):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.scatter(x, y, alpha=alpha, s=s)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if xlog:
        ax.set_xscale('log')
    if ylog:
        ax.set_yscale('log')
    savefig(out_path, fig)

def lineplot(xs, ys, xlabel, ylabel, title, out_path):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.plot(xs, ys)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    savefig(out_path, fig)

def hist(data, bins, xlabel, ylabel, title, out_path, logy=False, xlim=None):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.hist(data, bins=bins, edgecolor='black')
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if logy:
        ax.set_yscale('log')
    if xlim is not None:
        ax.set_xlim(xlim)
    savefig(out_path, fig)

def boxplot(groups, labels, xlabel, ylabel, title, out_path):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.boxplot(groups, tick_labels=labels, showfliers=False)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    savefig(out_path, fig)

def heatmap_corr(df, title, out_path):
    corr = df.corr(numeric_only=True)
    fig = plt.figure()
    ax = fig.add_subplot(111)
    im = ax.imshow(corr.values, aspect='auto')
    ax.set_xticks(range(len(corr.columns)))
    ax.set_xticklabels(corr.columns, rotation=45, ha='right')
    ax.set_yticks(range(len(corr.index)))
    ax.set_yticklabels(corr.index)
    ax.set_title(title)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    savefig(out_path, fig)
    return corr

def ecdf(series: pd.Series):
    vals = np.sort(series.dropna().values)
    if len(vals) == 0:
        return vals, np.array([])
    y = np.linspace(0, 1, len(vals), endpoint=True)
    return vals, y

def plot_cdf(series, title, out_path, logx=False, xmax=None):
    x, y = ecdf(series)
    fig = plt.figure()
    ax = fig.add_subplot(111)
    if len(x) > 0:
        ax.plot(x, y)
    ax.set_xlabel("cycles")
    ax.set_ylabel("CDF")
    ax.set_title(title)
    if logx:
        ax.set_xscale('log')
    if xmax is not None:
        ax.set_xlim(0, xmax)
    savefig(out_path, fig)

def percentiles(series, qs=(0.5, 0.9, 0.95, 0.99, 0.999)):
    res = {}
    s = series.dropna()
    if s.empty:
        for q in qs:
            res[f"p{int(q*1000) if q<1 else int(q*100)}"] = float('nan')
        res['min'] = res['max'] = res['mean'] = float('nan')
        res['std'] = 0.0
        res['count'] = 0
        return res
    for q in qs:
        res[f"p{int(q*1000) if q<1 else int(q*100)}"] = float(s.quantile(q))
    res['min'] = float(s.min())
    res['max'] = float(s.max())
    res['mean'] = float(s.mean())
    res['std'] = float(s.std(ddof=1)) if len(s) > 1 else 0.0
    res['count'] = int(s.shape[0])
    return res

# -----------------------
# Main analysis
# -----------------------

def main():
    ensure_dir(PLOTS_DIR)
    df = read_data(DATA_FILE)

    df_alloc = df[df['op'] == 'alloc'].copy()
    df_free  = df[df['op'] == 'free'].copy()
    df_alloc_tree = df_alloc[df_alloc['from_tree'] == True].copy()

    # Correlation (alloc only)
    if not df_alloc.empty:
        num_cols = ['size', 'tree_count', 'depth', 'cycles']
        corr_alloc = heatmap_corr(
            df_alloc[num_cols],
            "Alloc: correlation matrix",
            os.path.join(PLOTS_DIR, "alloc_corr_heatmap.png")
        )
        corr_alloc.to_csv(os.path.join(PLOTS_DIR, "alloc_corr.csv"))

    # Tree size vs cycles (alloc/free)
    if not df_alloc.empty:
        scatter(
            df_alloc['tree_count'], df_alloc['cycles'],
            "tree_count", "cycles", "Alloc: cycles vs. tree_count",
            os.path.join(PLOTS_DIR, "alloc_cycles_vs_tree_count.png"),
            alpha=0.25
        )
    if not df_free.empty:
        scatter(
            df_free['tree_count'], df_free['cycles'],
            "tree_count", "cycles", "Free: cycles vs. tree_count",
            os.path.join(PLOTS_DIR, "free_cycles_vs_tree_count.png"),
            alpha=0.25
        )

    # From-tree vs not (alloc only)
    if not df_alloc.empty:
        g_tree  = df_alloc.loc[df_alloc['from_tree'] == True,  'cycles'].dropna()
        g_not   = df_alloc.loc[df_alloc['from_tree'] == False, 'cycles'].dropna()
        boxplot(
            [g_tree, g_not],
            ["from_tree", "not_from_tree"],
            "alloc path", "cycles", "Alloc: cycles by from_tree",
            os.path.join(PLOTS_DIR, "alloc_cycles_by_from_tree_box.png"),
        )
        hist(
            g_tree, bins=100,
            xlabel="cycles", ylabel="count",
            title="Alloc (from_tree): cycles histogram",
            out_path=os.path.join(PLOTS_DIR, "alloc_from_tree_hist.png"),
            logy=True
        )
        hist(
            g_not, bins=100,
            xlabel="cycles", ylabel="count",
            title="Alloc (not_from_tree): cycles histogram",
            out_path=os.path.join(PLOTS_DIR, "alloc_not_from_tree_hist.png"),
            logy=True
        )

    # Depth vs cycles (alloc from_tree)
    if not df_alloc_tree.empty:
        scatter(
            df_alloc_tree['depth'], df_alloc_tree['cycles'],
            "tree depth", "cycles",
            "Alloc (from_tree): cycles vs. tree depth",
            os.path.join(PLOTS_DIR, "alloc_from_tree_cycles_vs_depth.png"),
            alpha=0.4
        )
        depth_stats = df_alloc_tree.groupby('depth')['cycles'].median().reset_index()
        lineplot(
            depth_stats['depth'], depth_stats['cycles'],
            "tree depth", "median cycles",
            "Alloc (from_tree): median cycles by depth",
            os.path.join(PLOTS_DIR, "alloc_from_tree_median_cycles_by_depth.png"),
        )

    # Size vs cycles (alloc/free)
    if not df_alloc.empty:
        scatter(
            df_alloc['size'], df_alloc['cycles'],
            "allocation size (bytes)", "cycles",
            "Alloc: cycles vs. size (log-x)",
            os.path.join(PLOTS_DIR, "alloc_cycles_vs_size_logx.png"),
            xlog=True, alpha=0.25
        )
    if not df_free.empty:
        scatter(
            df_free['size'], df_free['cycles'],
            "size (bytes)", "cycles",
            "Free: cycles vs. size (log-x)",
            os.path.join(PLOTS_DIR, "free_cycles_vs_size_logx.png"),
            xlog=True, alpha=0.25
        )

    # Over time (alloc/free)
    if not df_alloc.empty:
        lineplot(
            df_alloc['i'], df_alloc['cycles'],
            "operation index (alloc)", "cycles",
            "Alloc: cycles over time",
            os.path.join(PLOTS_DIR, "alloc_cycles_over_time.png"),
        )
    if not df_free.empty:
        lineplot(
            df_free['i'], df_free['cycles'],
            "operation index (free)", "cycles",
            "Free: cycles over time",
            os.path.join(PLOTS_DIR, "free_cycles_over_time.png"),
        )

    # Distributions: Hist + CDF (fixed + zoomed)
    def do_distribution_plots(series, prefix):
        s = series.dropna()
        if s.empty:
            return
        hist(
            s, bins=200, xlabel="cycles", ylabel="count",
            title=f"{prefix}: cycles histogram",
            out_path=os.path.join(PLOTS_DIR, f"{prefix.lower().replace(' ', '_')}_cycles_hist.png"),
            logy=True
        )
        plot_cdf(
            s, f"{prefix}: cycles CDF (log-x)",
            os.path.join(PLOTS_DIR, f"{prefix.lower().replace(' ', '_')}_cycles_cdf_logx.png"),
            logx=True
        )
        p_zoom = s.quantile(ZOOM_Q)
        xmax = float(p_zoom) * 1.001 if np.isfinite(p_zoom) else None
        hist(
            s[s <= p_zoom], bins=ZOOM_BINS, xlabel="cycles", ylabel="count",
            title=f"{prefix}: cycles histogram (≤ p{int(ZOOM_Q*100)} zoom)",
            out_path=os.path.join(PLOTS_DIR, f"{prefix.lower().replace(' ', '_')}_cycles_hist_zoom.png"),
            logy=False, xlim=(0, xmax)
        )
        plot_cdf(
            s[s <= p_zoom], f"{prefix}: cycles CDF (≤ p{int(ZOOM_Q*100)} zoom, log-x)",
            os.path.join(PLOTS_DIR, f"{prefix.lower().replace(' ', '_')}_cycles_cdf_zoom_logx.png"),
            logx=True, xmax=xmax
        )

    if not df_alloc.empty:
        do_distribution_plots(df_alloc['cycles'], "Alloc")
    if not df_free.empty:
        do_distribution_plots(df_free['cycles'], "Free")

    # Per-type medians
    if not df_alloc.empty:
        med_by_type_alloc = df_alloc.groupby('type')['cycles'].median().reindex(sorted(df_alloc['type'].unique()))
        fig = plt.figure()
        ax = fig.add_subplot(111)
        ax.bar(med_by_type_alloc.index, med_by_type_alloc.values)
        ax.set_xlabel("AllocType")
        ax.set_ylabel("median cycles")
        ax.set_title("Alloc: median cycles by AllocType")
        savefig(os.path.join(PLOTS_DIR, "alloc_median_cycles_by_type.png"), fig)

    if not df_free.empty:
        med_by_type_free = df_free.groupby('type')['cycles'].median().reindex(sorted(df_free['type'].unique()))
        fig = plt.figure()
        ax = fig.add_subplot(111)
        ax.bar(med_by_type_free.index, med_by_type_free.values)
        ax.set_xlabel("AllocType")
        ax.set_ylabel("median cycles")
        ax.set_title("Free: median cycles by AllocType")
        savefig(os.path.join(PLOTS_DIR, "free_median_cycles_by_type.png"), fig)

    # Tail summaries written to CSV (alloc/free + from_tree slices)
    summaries = []
    def add_summary(tag, series):
        s = percentiles(series)
        s['tag'] = tag
        summaries.append(s)

    if not df_alloc.empty:
        add_summary("alloc_all", df_alloc['cycles'])
        add_summary("alloc_from_tree", df_alloc.loc[df_alloc['from_tree']==True, 'cycles'])
        add_summary("alloc_not_from_tree", df_alloc.loc[df_alloc['from_tree']==False, 'cycles'])
        for t in sorted(df_alloc['type'].unique()):
            add_summary(f"alloc_type={t}", df_alloc.loc[df_alloc['type']==t, 'cycles'])
    if not df_free.empty:
        add_summary("free_all", df_free['cycles'])
        for t in sorted(df_free['type'].unique()):
            add_summary(f"free_type={t}", df_free.loc[df_free['type']==t, 'cycles'])

    if summaries:
        cols = ['tag','count','min','p500','p900','p950','p990','p999','mean','std','max']
        summ_df = pd.DataFrame(summaries)
        for c in cols:
            if c not in summ_df.columns:
                summ_df[c] = np.nan
        summ_df = summ_df[cols]
        summ_df.to_csv(os.path.join(PLOTS_DIR, "latency_summary.csv"), index=False)

    with open(os.path.join(PLOTS_DIR, "README.txt"), "w") as f:
        f.write("Generated plots and summaries:\n")
        for name in sorted(os.listdir(PLOTS_DIR)):
            if name.endswith((".png", ".csv", ".txt")):
                f.write(f" - {name}\n")

if __name__ == "__main__":
    main()
