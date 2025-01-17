import json
from pathlib import Path
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from datetime import datetime


def analyze_commit_timing(nvd_data_dir: str = "../../nvd_data"):
    # Track statistics about data availability
    total_cves = 0
    cves_with_commit_data = 0
    commit_times = []

    # Process all JSON files in the nvd_data directory
    nvd_path = Path(nvd_data_dir)
    for file_path in nvd_path.glob("*.json"):
        total_cves += 1

        try:
            with open(file_path) as f:
                vuln_data = json.load(f)

            # Check if we have commit details
            fix_commit_details = vuln_data.get("github_data", {}).get(
                "fix_commit_details"
            )

            if fix_commit_details and "commit_date" in fix_commit_details:
                cves_with_commit_data += 1

                # Parse the commit date
                commit_date = datetime.fromisoformat(
                    fix_commit_details["commit_date"].replace("Z", "+00:00")
                )

                commit_times.append(
                    {
                        "cve_id": vuln_data["cve_id"],
                        "day_of_week": commit_date.strftime("%A"),
                        "hour": commit_date.hour,
                        "commit_date": commit_date,
                    }
                )

        except Exception as e:
            print(f"Error processing {file_path}: {e}")

    # Create DataFrame from collected data
    df = pd.DataFrame(commit_times)

    # Print data availability statistics
    print(f"Total CVEs analyzed: {total_cves}")
    print(f"CVEs with commit timing data: {cves_with_commit_data}")
    print(f"Percentage with timing data: {(cves_with_commit_data/total_cves)*100:.2f}%")

    if not commit_times:
        print("No commit timing data found!")
        return

    # Create pivot table for heatmap
    day_order = [
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday",
    ]
    pivot_data = pd.crosstab(df["day_of_week"], df["hour"])
    pivot_data = pivot_data.reindex(day_order)

    # Create heatmap
    plt.figure(figsize=(15, 8))
    sns.heatmap(
        pivot_data,
        cmap="YlOrRd",
        annot=True,
        fmt="d",
        cbar_kws={"label": "Number of Commits"},
    )

    plt.title("Vulnerable Commit Frequency by Day and Hour (UTC)")
    plt.xlabel("Hour of Day (UTC)")
    plt.ylabel("Day of Week")

    # Save the plot
    plt.tight_layout()
    plt.savefig("commit_timing_heatmap.png")
    plt.close()

    # Additional statistics
    print("\nTiming Statistics:")
    print("\nMost Common Days:")
    print(df["day_of_week"].value_counts().head())

    print("\nMost Common Hours (UTC):")
    print(df["hour"].value_counts().head())

    # Calculate percentage of commits during working hours (9-5) vs off hours
    df["is_working_hours"] = (df["hour"].between(9, 17)) & (
        df["day_of_week"].isin(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"])
    )
    working_hours_pct = (df["is_working_hours"].sum() / len(df)) * 100

    print(
        f"\nPercentage of commits during working hours (9-5 UTC, Mon-Fri): {working_hours_pct:.2f}%"
    )
    print(f"Percentage of commits during off hours: {100-working_hours_pct:.2f}%")


if __name__ == "__main__":
    analyze_commit_timing()
