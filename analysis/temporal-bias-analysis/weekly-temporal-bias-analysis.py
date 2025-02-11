import json
from pathlib import Path
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime
import numpy as np
from scipy import stats


def analyze_cve_distribution(nvd_data_dir: str = "../../nvd_data"):
    # Lists to store data
    all_cves = []
    cves_with_commits = []

    # Process all JSON files
    nvd_path = Path(nvd_data_dir)
    for file_path in nvd_path.glob("*.json"):
        try:
            with open(file_path) as f:
                vuln_data = json.load(f)

            published_date = datetime.fromisoformat(
                vuln_data["temporal_data"]["published_date"].replace("Z", "+00:00")
            )

            # Store basic info for all CVEs
            all_cves.append(
                {
                    "cve_id": vuln_data["cve_id"],
                    "published_date": published_date,
                    "has_commit_data": False,
                }
            )

            # Check if we have commit details
            if vuln_data.get("github_data", {}).get("fix_commit_details"):
                cves_with_commits.append(
                    {
                        "cve_id": vuln_data["cve_id"],
                        "published_date": published_date,
                        "has_commit_data": True,
                    }
                )

        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    # Create DataFrames
    df_all = pd.DataFrame(all_cves)
    df_commits = pd.DataFrame(cves_with_commits)

    # Print statistics
    total_cves = len(df_all)
    cves_with_data = len(df_commits)
    print(f"Total CVEs: {total_cves}")
    print(f"CVEs with commit data: {cves_with_data}")
    print(f"Percentage with commit data: {(cves_with_data/total_cves)*100:.2f}%")

    # Create figure with four subplots
    fig = plt.figure(figsize=(15, 20))
    gs = fig.add_gridspec(4, 1)
    ax1 = fig.add_subplot(gs[0])
    ax2 = fig.add_subplot(gs[1])
    ax3 = fig.add_subplot(gs[2])
    ax4 = fig.add_subplot(gs[3])

    # Plot 1: Distribution comparison by year
    df_all["year"] = df_all["published_date"].dt.year
    df_commits["year"] = df_commits["published_date"].dt.year

    # Calculate yearly counts
    yearly_all = df_all["year"].value_counts().sort_index()
    yearly_commits = df_commits["year"].value_counts().sort_index()

    # Calculate percentages for years
    yearly_percentages = (yearly_commits / yearly_all * 100).fillna(0)

    # Plot the distributions
    ax1.bar(
        yearly_all.index, yearly_all.values, alpha=0.5, label="All CVEs", color="blue"
    )
    ax1.bar(
        yearly_commits.index,
        yearly_commits.values,
        alpha=0.7,
        label="CVEs with Commit Data",
        color="red",
    )

    ax1.set_title("Distribution of CVEs by Year")
    ax1.set_xlabel("Year")
    ax1.set_ylabel("Number of CVEs")
    ax1.legend()

    # Add percentage labels on top of bars
    for i, year in enumerate(yearly_all.index):
        if year in yearly_percentages.index:
            percentage = yearly_percentages[year]
            if percentage > 0:
                ax1.text(
                    year,
                    yearly_all[year],
                    f"{percentage:.1f}%",
                    ha="center",
                    va="bottom",
                )

    # Plot 2, 3, and 4: Switch to weekly aggregation
    # Add week number to both dataframes and resample to weeks
    df_all["week_start"] = df_all["published_date"].dt.to_period("W").dt.start_time
    df_commits["week_start"] = (
        df_commits["published_date"].dt.to_period("W").dt.start_time
    )

    weekly_all = df_all.groupby("week_start").size()
    weekly_commits = df_commits.groupby("week_start").size()

    # Calculate coverage percentage
    coverage_percentage = (weekly_commits / weekly_all * 100).fillna(0)

    # Plot 2: Raw Numbers vs Percentage Comparison with weekly data
    ax2_twin = ax2.twinx()

    # Plot raw numbers on primary y-axis
    line1 = ax2.plot(
        weekly_commits.index,
        weekly_commits.values,
        color="blue",
        marker=".",
        markersize=3,
        label="Number of CVEs with Commit Data",
    )
    ax2.set_ylabel("Number of CVEs with Commit Data", color="blue")
    ax2.tick_params(axis="y", labelcolor="blue")

    # Plot percentage on secondary y-axis
    line2 = ax2_twin.plot(
        coverage_percentage.index,
        coverage_percentage.values,
        color="red",
        marker=".",
        markersize=3,
        label="Percentage of CVEs with Commit Data",
    )
    ax2_twin.set_ylabel("Percentage of CVEs with Commit Data", color="red")
    ax2_twin.tick_params(axis="y", labelcolor="red")

    # Add legend
    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax2_twin.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, loc="upper right")

    ax2.set_title(
        "Weekly Comparison of Raw Numbers vs Percentage of CVEs with Commit Data"
    )
    ax2.set_xlabel("Week")
    ax2.grid(True)

    # Rotate x-axis labels for better readability
    plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45)

    # Plot 3: Regression for number of CVEs with commit data (weekly)
    dates_ordinal = [d.toordinal() for d in weekly_commits.index]
    slope, intercept, r_value, p_value, std_err = stats.linregress(
        dates_ordinal, weekly_commits.values
    )

    # Create regression line
    line_dates = np.array([min(dates_ordinal), max(dates_ordinal)])
    line_values = slope * line_dates + intercept

    ax3.scatter(
        weekly_commits.index,
        weekly_commits.values,
        color="blue",
        alpha=0.5,
        s=20,
        label="Weekly data",
    )
    ax3.plot(
        [datetime.fromordinal(int(d)) for d in line_dates],
        line_values,
        color="red",
        label=f"Regression line (R² = {r_value**2:.3f})",
    )

    ax3.set_title(
        "Regression Analysis: Number of CVEs with Commit Data Over Time (Weekly)"
    )
    ax3.set_xlabel("Week")
    ax3.set_ylabel("Number of CVEs with Commit Data")
    ax3.legend()
    plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45)

    # Plot 4: Regression for percentage of CVEs with commit data (weekly)
    dates_ordinal = [d.toordinal() for d in coverage_percentage.index]
    slope, intercept, r_value, p_value, std_err = stats.linregress(
        dates_ordinal, coverage_percentage.values
    )

    # Create regression line
    line_dates = np.array([min(dates_ordinal), max(dates_ordinal)])
    line_values = slope * line_dates + intercept

    ax4.scatter(
        coverage_percentage.index,
        coverage_percentage.values,
        color="blue",
        alpha=0.5,
        s=20,
        label="Weekly data",
    )
    ax4.plot(
        [datetime.fromordinal(int(d)) for d in line_dates],
        line_values,
        color="red",
        label=f"Regression line (R² = {r_value**2:.3f})",
    )

    ax4.set_title(
        "Regression Analysis: Percentage of CVEs with Commit Data Over Time (Weekly)"
    )
    ax4.set_xlabel("Week")
    ax4.set_ylabel("Percentage of CVEs with Commit Data")
    ax4.legend()
    plt.setp(ax4.xaxis.get_majorticklabels(), rotation=45)

    # Adjust layout and save
    plt.tight_layout()
    plt.savefig("weekly_cve_temporal_distribution.png")
    plt.close()


if __name__ == "__main__":
    analyze_cve_distribution()
