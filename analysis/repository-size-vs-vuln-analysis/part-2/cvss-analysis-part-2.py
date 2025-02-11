import json
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from typing import Dict, List
from tqdm import tqdm  # For progress tracking


def load_vulnerability_data(nvd_data_dir: str = "../../../nvd_data") -> pd.DataFrame:
    """Load and process vulnerability data from JSON files with improved error handling."""
    data: List[Dict] = []

    # Use tqdm for progress tracking
    files = list(Path(nvd_data_dir).glob("*.json"))
    for file_path in tqdm(files, desc="Processing vulnerability data"):
        try:
            with open(file_path) as f:
                vuln = json.load(f)
                if vuln.get("repository_context"):  # Safer dictionary access
                    cvss_score = vuln.get("vulnerability_details", {}).get("cvss_score")
                    if cvss_score is not None:  # Explicit null check
                        data.append(
                            {
                                "repo_size": vuln["repository_context"]["size"],
                                "vulnerabilities": 1,
                                "cvss_score": cvss_score,
                            }
                        )
        except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
            print(f"Error processing {file_path}: {str(e)}")
            continue

    # Convert to DataFrame first, then aggregate
    df = pd.DataFrame(data)
    if df.empty:
        raise ValueError("No valid vulnerability data found")

    # Aggregate using pandas operations (more efficient than defaultdict)
    grouped = (
        df.groupby("repo_size")
        .agg({"vulnerabilities": "count", "cvss_score": "mean"})
        .reset_index()
    )

    grouped.rename(columns={"cvss_score": "avg_cvss"}, inplace=True)
    return grouped


def create_visualizations(df: pd.DataFrame) -> plt.Figure:
    """Create improved visualizations with better handling of outliers and density."""
    fig = plt.figure(figsize=(20, 16))
    gs = fig.add_gridspec(2, 2)

    # 1. Linear scale scatter plot with alpha adjustment and size mapping
    ax1 = fig.add_subplot(gs[0, 0])
    scatter1 = ax1.scatter(
        df["repo_size"],
        df["vulnerabilities"],
        c=df["avg_cvss"],
        cmap="RdYlBu_r",
        alpha=0.6,
        s=50 * (df["avg_cvss"] / df["avg_cvss"].max()),  # Size points by CVSS score
    )
    ax1.set_xlabel("Repository Size (KB)")
    ax1.set_ylabel("Number of Vulnerabilities")
    ax1.set_title("Repository Size vs. Vulnerabilities (Linear Scale)")
    plt.colorbar(scatter1, ax=ax1, label="Average CVSS Score")

    # Set reasonable y-axis limits based on data distribution
    ylim = np.percentile(df["vulnerabilities"], 99.5)  # Exclude extreme outliers
    ax1.set_ylim(0, ylim)

    # 2. Log scale scatter plot with improved visibility
    ax2 = fig.add_subplot(gs[0, 1])
    scatter2 = ax2.scatter(
        df["repo_size"],
        df["vulnerabilities"],
        c=df["avg_cvss"],
        cmap="RdYlBu_r",
        alpha=0.6,
        s=50 * (df["avg_cvss"] / df["avg_cvss"].max()),
    )
    ax2.set_xscale("log")
    ax2.set_xlabel("Repository Size (KB)")
    ax2.set_ylabel("Number of Vulnerabilities")
    ax2.set_title("Repository Size vs. Vulnerabilities (Log Scale)")
    plt.colorbar(scatter2, ax=ax2, label="Average CVSS Score")
    ax2.set_ylim(0, ylim)

    # 3. Box plot with improved binning
    ax3 = fig.add_subplot(gs[1, 0])
    # Create logarithmic size bins for more meaningful distribution
    df["size_bin"] = pd.qcut(
        np.log10(df["repo_size"]),
        q=10,
        labels=["Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8", "Q9", "Q10"],
    )
    sns.boxplot(data=df, x="size_bin", y="vulnerabilities", ax=ax3, showfliers=False)
    ax3.set_xlabel("Repository Size Decile (Log Scale)")
    ax3.set_ylabel("Number of Vulnerabilities")
    ax3.set_title("Vulnerability Distribution by Repository Size")

    # 4. Density heatmap with improved binning and scaling
    ax4 = fig.add_subplot(gs[1, 1])
    h = ax4.hist2d(
        np.log10(df["repo_size"]),
        df["vulnerabilities"],
        bins=50,
        cmap="YlOrRd",
        norm=plt.cm.colors.LogNorm(),
        range=[[0, np.log10(df["repo_size"]).max()], [0, ylim]],
    )
    ax4.set_xlabel("Log10(Repository Size KB)")
    ax4.set_ylabel("Number of Vulnerabilities")
    ax4.set_title("Density of Repository Size vs. Vulnerabilities")
    plt.colorbar(h[3], ax=ax4, label="Count")

    plt.tight_layout()
    return fig


def main():
    try:
        # Load and process data
        df = load_vulnerability_data()

        # Create visualizations
        fig = create_visualizations(df)

        # Save the figure with high quality
        plt.savefig("vulnerability_analysis_part_2.png", dpi=300, bbox_inches="tight")
        plt.close()

        # Save processed data
        df.to_csv("vulnerability_analysis.csv", index=False)

    except Exception as e:
        print(f"Error in analysis: {str(e)}")


if __name__ == "__main__":
    main()
