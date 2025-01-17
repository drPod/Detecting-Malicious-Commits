import json
from pathlib import Path
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime
import numpy as np


def analyze_vulnerability_severity_trends(
    nvd_data_dir: str = "../../nvd_data", start_year: int = 2017, end_year: int = 2024
):
    """Analyze and visualize vulnerability trends with severity overlay."""

    # Lists to store vulnerability data
    vulnerabilities = []

    # Process all JSON files
    nvd_path = Path(nvd_data_dir)
    for file_path in nvd_path.glob("*.json"):
        try:
            with open(file_path) as f:
                vuln_data = json.load(f)

            # Extract relevant data
            published_date = datetime.fromisoformat(
                vuln_data["temporal_data"]["published_date"].replace("Z", "+00:00")
            )
            cvss_score = vuln_data["vulnerability_details"]["cvss_score"]

            # Only include if we have both date and CVSS score
            if published_date and cvss_score:
                vulnerabilities.append(
                    {
                        "date": published_date,
                        "cvss_score": cvss_score,
                        # Categorize severity based on CVSS score
                        "severity": (
                            "Critical"
                            if cvss_score >= 9.0
                            else (
                                "High"
                                if cvss_score >= 7.0
                                else "Medium" if cvss_score >= 4.0 else "Low"
                            )
                        ),
                    }
                )

        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    # Create DataFrame
    df = pd.DataFrame(vulnerabilities)

    # Add year and month columns
    df["year"] = df["date"].dt.year
    df["month"] = df["date"].dt.month
    df["yearmonth"] = pd.to_datetime(df["date"].dt.strftime("%Y-%m"))

    # Filter for desired year range
    df = df[(df["year"] >= start_year) & (df["year"] <= end_year)]

    # Group by year-month and severity
    monthly_severity = (
        df.groupby(["yearmonth", "severity"]).size().unstack(fill_value=0)
    )
    monthly_total = df.groupby("yearmonth").size()

    # Calculate percentage for each severity level
    severity_pcts = monthly_severity.div(monthly_total, axis=0) * 100

    # Create the visualization
    plt.figure(figsize=(15, 10))

    # Plot total vulnerabilities line
    ax1 = plt.gca()
    ax2 = ax1.twinx()

    # Plot the stacked percentage areas
    severity_pcts.plot(
        kind="area",
        stacked=True,
        alpha=0.4,
        ax=ax2,
        color={
            "Critical": "#FF0000",
            "High": "#FF6B6B",
            "Medium": "#FFD93D",
            "Low": "#95CD41",
        },
    )

    # Plot the total number line
    monthly_total.plot(
        color="black", linewidth=2, ax=ax1, label="Total Vulnerabilities"
    )

    # Customize the plot
    ax1.set_title("Vulnerability Trends and Severity Distribution (2017-2024)", pad=20)
    ax1.set_xlabel("Date")
    ax1.set_ylabel("Total Number of Vulnerabilities", color="black")
    ax2.set_ylabel("Severity Distribution (%)")

    # Add legends
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(
        lines1 + lines2, labels1 + labels2, loc="upper left", bbox_to_anchor=(1.15, 1)
    )

    # Rotate x-axis labels
    plt.xticks(rotation=45)

    # Add annotations for key statistics
    total_vulns = len(df)
    avg_cvss = df["cvss_score"].mean()
    pct_critical = (df["severity"] == "Critical").mean() * 100

    stats_text = (
        f"Total Vulnerabilities: {total_vulns:,}\n"
        f"Average CVSS Score: {avg_cvss:.2f}\n"
        f"Critical Vulnerabilities: {pct_critical:.1f}%"
    )

    plt.figtext(0.02, 0.02, stats_text, fontsize=10, ha="left")

    # Adjust layout and save
    plt.tight_layout()
    plt.savefig("vulnerability_severity_trends.png", bbox_inches="tight", dpi=300)
    plt.close()

    # Print additional statistics
    print("\nVulnerability Severity Statistics (2017-2024):")
    print("-" * 50)
    print(f"Total vulnerabilities analyzed: {total_vulns:,}")
    print(f"Average CVSS score: {avg_cvss:.2f}")
    print("\nSeverity Distribution:")
    severity_dist = df["severity"].value_counts()
    for severity, count in severity_dist.items():
        print(f"{severity}: {count:,} ({count/total_vulns*100:.1f}%)")

    # Trend analysis
    yearly_stats = df.groupby("year").agg(
        {
            "cvss_score": ["mean", "count"],
            "severity": lambda x: (x == "Critical").mean() * 100,
        }
    )

    print("\nYearly Trends:")
    print("-" * 50)
    for year in yearly_stats.index:
        print(f"\n{year}:")
        print(
            f"  Total vulnerabilities: {yearly_stats.loc[year, ('cvss_score', 'count')]:,}"
        )
        print(f"  Average CVSS: {yearly_stats.loc[year, ('cvss_score', 'mean')]:.2f}")
        print(
            f"  Percentage Critical: {yearly_stats.loc[year, ('severity', '<lambda>')]:.1f}%"
        )


if __name__ == "__main__":
    analyze_vulnerability_severity_trends()
