#!/usr/bin/env python3
import argparse
import os
import math
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

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

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def savefig(path: str, fig=None):
    if fig is None:
        fig = plt.gcf()
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)

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

def hist(data, bins, xlabel, ylabel, title, out_path, logy=False):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.hist(data, bins=bins, edgecolor='black')
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    if logy:
        ax.set_yscale('log')
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

def percentiles(series, qs=(0.5, 0.95, 0.99)):
    res = {}
    for q in qs:
        res[f"p{int(q*100)}"] = float(series.quantile(q))
    res['mean'] = float(series.mean())
    res['std'] = float(series.std(ddof=1) if len(series) > 1 else 0.0)
    res['count'] = int(series.shape[0])
    return res

def main():
    parser = argparse.ArgumentParser(description="Heap latency CSV analysis and plots")
    parser.add_argument("csv_path", help="Path to heap_latency.csv")
    parser.add_argument("--outdir", default="heap_plots", help="Output directory for plots and summaries")
    args = parser.parse_args()

    ensure_dir(args.outdir)
    df = read_data(args.csv_path)

    df_alloc = df[df['op'] == 'alloc'].copy()
    df_free  = df[df['op'] == 'free'].copy()

    # 1) Tree size vs cycles (alloc)
    if not df_alloc.empty:
        scatter(
            df_alloc['tree_count'], df_alloc['cycles'],
            xlabel="tree_count",
            ylabel="cycles",
            title="Alloc: cycles vs. tree_count",
            out_path=os.path.join(args.outdir, "alloc_cycles_vs_tree_count.png"),
            xlog=False, ylog=False, alpha=0.25
        )
    # 1b) Tree size vs cycles (free)
    if not df_free.empty:
        scatter(
            df_free['tree_count'], df_free['cycles'],
            xlabel="tree_count",
            ylabel="cycles",
            title="Free: cycles vs. tree_count",
            out_path=os.path.join(args.outdir, "free_cycles_vs_tree_count.png"),
            xlog=False, ylog=False, alpha=0.25
        )

    # 2) From-tree vs not (alloc only) -> use boxplot and also hist per class
    if not df_alloc.empty:
        groups = [
            df_alloc.loc[df_alloc['from_tree'] == True, 'cycles'].dropna(),
            df_alloc.loc[df_alloc['from_tree'] == False, 'cycles'].dropna(),
        ]
        labels = ["from_tree", "not_from_tree"]
        boxplot(
            groups, labels,
            xlabel="alloc path",
            ylabel="cycles",
            title="Alloc: cycles by from_tree",
            out_path=os.path.join(args.outdir, "alloc_cycles_by_from_tree_box.png"),
        )
        hist(
            groups[0], bins=100,
            xlabel="cycles",
            ylabel="count",
            title="Alloc (from_tree): cycles histogram",
            out_path=os.path.join(args.outdir, "alloc_from_tree_hist.png"),
            logy=True
        )
        hist(
            groups[1], bins=100,
            xlabel="cycles",
            ylabel="count",
            title="Alloc (not_from_tree): cycles histogram",
            out_path=os.path.join(args.outdir, "alloc_not_from_tree_hist.png"),
            logy=True
        )

    # 3) Tree depth vs cycles (alloc only, from_tree)
    df_alloc_tree = df_alloc[df_alloc['from_tree'] == True].copy()
    if not df_alloc_tree.empty:
        scatter(
            df_alloc_tree['depth'], df_alloc_tree['cycles'],
            xlabel="tree depth",
            ylabel="cycles",
            title="Alloc (from_tree): cycles vs. tree depth",
            out_path=os.path.join(args.outdir, "alloc_from_tree_cycles_vs_depth.png"),
            xlog=False, ylog=False, alpha=0.4
        )
        depth_stats = df_alloc_tree.groupby('depth')['cycles'].median().reset_index()
        lineplot(
            depth_stats['depth'], depth_stats['cycles'],
            xlabel="tree depth",
            ylabel="median cycles",
            title="Alloc (from_tree): median cycles by depth",
            out_path=os.path.join(args.outdir, "alloc_from_tree_median_cycles_by_depth.png"),
        )

    # 4) Cycles vs allocation size (allocations)
    if not df_alloc.empty:
        scatter(
            df_alloc['size'], df_alloc['cycles'],
            xlabel="allocation size (bytes)",
            ylabel="cycles",
            title="Alloc: cycles vs. size (log-x)",
            out_path=os.path.join(args.outdir, "alloc_cycles_vs_size_logx.png"),
            xlog=True, ylog=False, alpha=0.25
        )

    # 5) Alloc vs free distributions (separate histograms and CDFs)
    if not df_alloc.empty:
        hist(
            df_alloc['cycles'].dropna(), bins=200,
            xlabel="cycles",
            ylabel="count",
            title="Alloc: cycles histogram",
            out_path=os.path.join(args.outdir, "alloc_cycles_hist.png"),
            logy=True
        )
        fig = plt.figure()
        ax = fig.add_subplot(111)
        vals = np.sort(df_alloc['cycles'].dropna().values)
        if len(vals) > 0:
            ax.plot(vals, np.linspace(0, 1, len(vals), endpoint=True))
        ax.set_xlabel("cycles")
        ax.set_ylabel("CDF")
        ax.set_title("Alloc: cycles CDF")
        savefig(os.path.join(args.outdir, "alloc_cycles_cdf.png"), fig)

    if not df_free.empty:
        hist(
            df_free['cycles'].dropna(), bins=200,
            xlabel="cycles",
            ylabel="count",
            title="Free: cycles histogram",
            out_path=os.path.join(args.outdir, "free_cycles_hist.png"),
            logy=True
        )
        fig = plt.figure()
        ax = fig.add_subplot(111)
        vals = np.sort(df_free['cycles'].dropna().values)
        if len(vals) > 0:
            ax.plot(vals, np.linspace(0, 1, len(vals), endpoint=True))
        ax.set_xlabel("cycles")
        ax.set_ylabel("CDF")
        ax.set_title("Free: cycles CDF")
        savefig(os.path.join(args.outdir, "free_cycles_cdf.png"), fig)

    # 6) Per-type latency (median) for alloc and free
    if not df_alloc.empty:
        med_by_type_alloc = df_alloc.groupby('type')['cycles'].median().reindex(sorted(df_alloc['type'].unique()))
        fig = plt.figure()
        ax = fig.add_subplot(111)
        ax.bar(med_by_type_alloc.index, med_by_type_alloc.values)
        ax.set_xlabel("AllocType")
        ax.set_ylabel("median cycles")
        ax.set_title("Alloc: median cycles by AllocType")
        savefig(os.path.join(args.outdir, "alloc_median_cycles_by_type.png"), fig)

    if not df_free.empty:
        med_by_type_free = df_free.groupby('type')['cycles'].median().reindex(sorted(df_free['type'].unique()))
        fig = plt.figure()
        ax = fig.add_subplot(111)
        ax.bar(med_by_type_free.index, med_by_type_free.values)
        ax.set_xlabel("AllocType")
        ax.set_ylabel("median cycles")
        ax.set_title("Free: median cycles by AllocType")
        savefig(os.path.join(args.outdir, "free_median_cycles_by_type.png"), fig)

    # 7) Cycles vs op index i (alloc and free)
    if not df_alloc.empty:
        lineplot(
            df_alloc['i'], df_alloc['cycles'],
            xlabel="operation index (alloc)",
            ylabel="cycles",
            title="Alloc: cycles over time",
            out_path=os.path.join(args.outdir, "alloc_cycles_over_time.png"),
        )
    if not df_free.empty:
        lineplot(
            df_free['i'], df_free['cycles'],
            xlabel="operation index (free)",
            ylabel="cycles",
            title="Free: cycles over time",
            out_path=os.path.join(args.outdir, "free_cycles_over_time.png"),
        )

    # 8) Tail latency summaries
    summaries = []
    def add_summary(tag, series):
        s = percentiles(series.dropna())
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
        summ_df = pd.DataFrame(summaries)[['tag','count','mean','std','p50','p95','p99']]
        summ_df.to_csv(os.path.join(args.outdir, "latency_summary.csv"), index=False)

    # 9) Correlation matrices
    num_cols = ['size', 'tree_count', 'depth', 'cycles']
    if not df_alloc.empty:
        corr_alloc = heatmap_corr(df_alloc[num_cols], "Alloc: correlation matrix", os.path.join(args.outdir, "alloc_corr_heatmap.png"))
        corr_alloc.to_csv(os.path.join(args.outdir, "alloc_corr.csv"))
    if not df_alloc_tree.empty:
        corr_alloc_tree = heatmap_corr(df_alloc_tree[num_cols], "Alloc(from_tree): correlation matrix", os.path.join(args.outdir, "alloc_from_tree_corr_heatmap.png"))
        corr_alloc_tree.to_csv(os.path.join(args.outdir, "alloc_from_tree_corr.csv"))

    # 10) Additional scatter: cycles vs size for frees (for completeness)
    if not df_free.empty:
        scatter(
            df_free['size'], df_free['cycles'],
            xlabel="size (bytes)",
            ylabel="cycles",
            title="Free: cycles vs. size (log-x)",
            out_path=os.path.join(args.outdir, "free_cycles_vs_size_logx.png"),
            xlog=True, ylog=False, alpha=0.25
        )

    with open(os.path.join(args.outdir, "README.txt"), "w") as f:
        f.write("Generated plots and summaries:\n")
        for root, _, files in os.walk(args.outdir):
            for name in sorted(files):
                f.write(f" - {name}\n")

if __name__ == "__main__":
    main()
