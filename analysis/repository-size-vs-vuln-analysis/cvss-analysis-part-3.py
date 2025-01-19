import json
from pathlib import Path
import matplotlib.pyplot as plt
import matplotlib.colors as colors  # Added import for LogNorm
import numpy as np
import pandas as pd
import seaborn as sns
from typing import Dict, List, Tuple
from tqdm import tqdm
from scipy import stats


def load_and_process_data(nvd_data_dir: str = "../../nvd_data") -> pd.DataFrame:
    """Load and process vulnerability data with enhanced statistical analysis."""
    data: List[Dict] = []

    for file_path in tqdm(
        list(Path(nvd_data_dir).glob("*.json")), desc="Processing files"
    ):
        try:
            with open(file_path) as f:
                vuln = json.load(f)
                if vuln.get("repository_context"):
                    cvss_score = vuln.get("vulnerability_details", {}).get("cvss_score")
                    severity = (
                        get_severity_level(cvss_score)
                        if cvss_score is not None
                        else "Unknown"
                    )
                    data.append(
                        {
                            "repo_size": vuln["repository_context"]["size"],
                            "vulnerabilities": 1,
                            "cvss_score": cvss_score if cvss_score is not None else 0,
                            "severity": severity,
                        }
                    )
        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}")
            continue

    df = pd.DataFrame(data)
    if df.empty:
        raise ValueError("No valid vulnerability data found")

    # Calculate additional metrics
    grouped = (
        df.groupby("repo_size")
        .agg(
            {
                "vulnerabilities": "count",
                "cvss_score": ["mean", "std"],
            }
        )
        .reset_index()
    )

    # Flatten column names properly
    grouped.columns = ["repo_size", "vulnerabilities", "avg_cvss", "std_cvss"]

    # Add normalized metrics
    grouped["vuln_density"] = grouped["vulnerabilities"] / grouped["repo_size"]

    return grouped


def get_severity_level(cvss_score: float) -> str:
    """Determine CVSS severity level."""
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    else:
        return "Low"


def create_enhanced_visualizations(df: pd.DataFrame) -> plt.Figure:
    """Create enhanced visualizations with additional insights."""
    fig = plt.figure(figsize=(20, 20))
    gs = fig.add_gridspec(3, 2)  # Changed to 3x2 grid

    # 1. Enhanced scatter plot (log scales)
    ax1 = fig.add_subplot(gs[0, 0])
    scatter1 = ax1.scatter(
        df["repo_size"],
        df["vulnerabilities"],
        c=df["avg_cvss"],
        cmap="RdYlBu_r",
        alpha=0.6,
        s=100 * (df["std_cvss"] + 1),  # Size represents variability
    )
    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.set_xlabel("Repository Size (KB) - Log Scale")
    ax1.set_ylabel("Number of Vulnerabilities - Log Scale")
    ax1.set_title(
        "Repository Size vs. Vulnerabilities\n(Log-Log Scale, Point size indicates CVSS score variance)"
    )

    # Add trend line (calculated on log scale)
    log_x = np.log10(df["repo_size"])
    log_y = np.log10(df["vulnerabilities"])
    z = np.polyfit(log_x[np.isfinite(log_y)], log_y[np.isfinite(log_y)], 1)
    p = np.poly1d(z)
    x_range = np.logspace(
        np.log10(df["repo_size"].min()), np.log10(df["repo_size"].max()), 100
    )
    ax1.plot(x_range, 10 ** p(np.log10(x_range)), "r--", alpha=0.5)

    plt.colorbar(scatter1, ax=ax1, label="Average CVSS Score")

    # 2. Enhanced log scale plot
    ax2 = fig.add_subplot(gs[0, 1])
    scatter2 = ax2.scatter(
        df["repo_size"],
        df["vulnerabilities"],
        c=df["avg_cvss"],
        cmap="RdYlBu_r",
        alpha=0.6,
        s=100 * (df["std_cvss"] + 1),
    )
    ax2.set_xscale("log")
    ax2.set_yscale("log")
    ax2.set_xlabel("Repository Size (KB) - Log Scale")
    ax2.set_ylabel("Number of Vulnerabilities - Log Scale")
    ax2.set_title("Repository Size vs. Vulnerabilities\n(Log-Log Scale)")
    plt.colorbar(scatter2, ax=ax2, label="Average CVSS Score")

    # 3. Vulnerability density plot
    ax3 = fig.add_subplot(gs[1, 0])
    sns.scatterplot(
        data=df,
        x="repo_size",
        y="vuln_density",
        hue="avg_cvss",
        palette="RdYlBu_r",
        ax=ax3,
    )
    ax3.set_xscale("log")
    ax3.set_yscale("log")
    ax3.set_xlabel("Repository Size (KB)")
    ax3.set_ylabel("Vulnerabilities per KB")
    ax3.set_title("Vulnerability Density vs. Repository Size")

    # 4. Enhanced heatmap (now with proper log scaling)
    ax4 = fig.add_subplot(gs[1, 1])

    # Create log-spaced bins
    x_bins = np.logspace(
        np.log10(df["repo_size"].min()), np.log10(df["repo_size"].max()), 50
    )
    y_bins = np.logspace(
        np.log10(max(df["vulnerabilities"].min(), 0.1)),  # Avoid log(0)
        np.log10(df["vulnerabilities"].max()),
        50,
    )

    # Calculate 2D histogram with log-spaced bins
    hist, xedges, yedges = np.histogram2d(
        df["repo_size"], df["vulnerabilities"], bins=[x_bins, y_bins]
    )

    # Use pcolormesh for proper log scaling
    X, Y = np.meshgrid(xedges, yedges)
    pcm = ax4.pcolormesh(
        X,
        Y,
        hist.T,
        norm=colors.LogNorm(
            vmin=max(1, hist.min()), vmax=hist.max()
        ),  # Updated to use colors.LogNorm
        cmap="YlOrRd",
    )

    ax4.set_xscale("log")
    ax4.set_yscale("log")
    ax4.set_xlabel("Repository Size (KB) - Log Scale")
    ax4.set_ylabel("Number of Vulnerabilities - Log Scale")
    ax4.set_title("Density Distribution (Log-Log Scale)")
    plt.colorbar(pcm, ax=ax4, label="Count (log scale)")

    # 5. CVSS Distribution
    ax5 = fig.add_subplot(gs[2, 0])
    sns.violinplot(data=df, y="avg_cvss", ax=ax5)
    ax5.set_title("Distribution of Average CVSS Scores")
    ax5.set_ylabel("Average CVSS Score")

    # 6. Correlation matrix
    ax6 = fig.add_subplot(gs[2, 1])
    correlation_data = df[
        ["repo_size", "vulnerabilities", "avg_cvss", "vuln_density", "std_cvss"]
    ].corr()
    sns.heatmap(correlation_data, annot=True, cmap="RdBu", center=0, ax=ax6)
    ax6.set_title("Correlation Matrix")

    plt.tight_layout()
    return fig


def generate_statistical_report(df: pd.DataFrame) -> str:
    """Generate a statistical report of the vulnerability analysis."""
    report = [
        "Statistical Analysis Report",
        "========================\n",
        f"Total Repositories Analyzed: {len(df)}",
        f"Total Vulnerabilities: {df['vulnerabilities'].sum()}",
        f"\nRepository Size Statistics:",
        f"  Median Size: {df['repo_size'].median():,.0f} KB",
        f"  Mean Size: {df['repo_size'].mean():,.0f} KB",
        f"\nVulnerability Statistics:",
        f"  Mean Vulnerabilities per Repo: {df['vulnerabilities'].mean():.2f}",
        f"  Median Vulnerabilities per Repo: {df['vulnerabilities'].median():.2f}",
        f"\nCVSS Score Statistics:",
        f"  Mean CVSS Score: {df['avg_cvss'].mean():.2f}",
        f"  Median CVSS Score: {df['avg_cvss'].median():.2f}",
        f"\nCorrelation Analysis:",
        f"  Size-Vulnerability Correlation: {df['repo_size'].corr(df['vulnerabilities']):.3f}",
        f"  Size-CVSS Correlation: {df['repo_size'].corr(df['avg_cvss']):.3f}",
    ]
    return "\n".join(report)


def main():
    try:
        # Load and process data
        df = load_and_process_data()

        # Create visualizations
        fig = create_enhanced_visualizations(df)
        plt.savefig("vulnerability_analysis_part_3.png", dpi=300, bbox_inches="tight")
        plt.close()

        # Generate and save statistical report
        report = generate_statistical_report(df)
        with open("vulnerability_analysis_report.txt", "w") as f:
            f.write(report)

        # Save processed data
        df.to_csv("vulnerability_analysis_enhanced.csv", index=False)

    except Exception as e:
        print(f"Error in analysis: {str(e)}")


if __name__ == "__main__":
    main()
