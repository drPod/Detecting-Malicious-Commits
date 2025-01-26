# enhanced_data_reporter.py
import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from tqdm import tqdm
import textwrap

plt.style.use("ggplot")
sns.set_palette("husl")


class EnhancedDataReporter:
    def __init__(self, data_dir: str = "../../nvd_data"):
        self.data_dir = Path(data_dir)
        self.files = list(self.data_dir.glob("*.json"))
        self.total_files = len(self.files)
        self.missing_counts = defaultdict(int)
        self.field_categories = {
            "Commit Metadata": [
                "github_data.fix_commit_details",
                "github_data.fix_commit_details.sha",
                "github_data.fix_commit_details.commit_date",
            ],
            "Author Behavior": [
                "github_data.fix_commit_details.author.stats.total_commits",
                "github_data.fix_commit_details.author.stats.average_weekly_commits",
            ],
            "Repository Context": [
                "repository_context.name",
                "repository_context.owner",
                "repository_context.security_features",
            ],
            "Code Changes": [
                "github_data.fix_commit_details.file_patterns.security_files",
                "github_data.fix_commit_details.file_patterns.dependency_files",
            ],
        }
        self.root_causes = {
            "Commit Metadata": "Deleted repositories or force-pushed commit history",
            "Author Behavior": "Private contributor profiles or API rate limiting",
            "Repository Context": "Archived/renamed repositories or access restrictions",
            "Code Changes": "Patch files unavailable or non-parseable diffs",
        }
        self.temporal_data = []
        self.report_content = []

    def generate_report(self):
        """Main method to generate complete report"""
        self._analyze_missing_data()
        self._calculate_quality_metrics()
        self._generate_visualizations()
        self._compile_report()
        return self.report_content

    def _analyze_missing_data(self):
        """Analyze JSON files with progress tracking"""
        for file_path in tqdm(self.files, desc="Analyzing files"):
            try:
                with open(file_path) as f:
                    data = json.load(f)
                    self._check_fields(data)
                    self._capture_temporal_data(data)
            except Exception as e:
                self._log_error(f"Error processing {file_path.name}: {str(e)}")

    def _check_fields(self, data: dict):
        """Check for missing fields in a record"""
        for category, fields in self.field_categories.items():
            for field in fields:
                if not self._nested_field_exists(data, field):
                    self.missing_counts[field] += 1

    def _capture_temporal_data(self, data: dict):
        """Capture temporal aspects of missing data"""
        pub_date = data.get("temporal_data", {}).get("published_date")
        if pub_date:
            try:
                year = int(pub_date[:4])
                missing_fields = sum(
                    1
                    for field in self.field_categories["Commit Metadata"]
                    if not self._nested_field_exists(data, field)
                )
                self.temporal_data.append({"year": year, "missing": missing_fields})
            except ValueError:
                pass

    def _calculate_quality_metrics(self):
        """Calculate quality metrics and scores"""
        self.missing_pct = {
            k: (v / self.total_files) * 100 for k, v in self.missing_counts.items()
        }
        self.category_scores = {
            cat: 100 - np.mean([self.missing_pct[f] for f in fields])
            for cat, fields in self.field_categories.items()
        }
        self.overall_score = np.mean(list(self.category_scores.values()))

    def _generate_visualizations(self):
        """Generate all visualizations"""
        self._create_category_plot()
        self._create_temporal_analysis()
        self._create_heatmap()
        self._create_score_radar()

    def _create_category_plot(self):
        """Create missing data category plot"""
        df = pd.DataFrame(
            {
                "Category": list(self.category_scores.keys()),
                "Completeness Score": list(self.category_scores.values()),
            }
        )

        plt.figure(figsize=(12, 6))
        ax = sns.barplot(x="Completeness Score", y="Category", data=df)
        plt.title("Data Completeness by Category", fontsize=14, pad=20)
        plt.xlim(0, 100)
        ax.bar_label(ax.containers[0], fmt="%.1f%%")
        plt.savefig("completeness_categories.png", bbox_inches="tight")
        plt.close()

    def _create_temporal_analysis(self):
        """Create temporal missingness analysis"""
        if not self.temporal_data:
            return

        df = pd.DataFrame(self.temporal_data)
        yearly_stats = df.groupby("year")["missing"].mean().reset_index()

        plt.figure(figsize=(12, 6))
        sns.lineplot(x="year", y="missing", data=yearly_stats, marker="o")
        plt.title("Average Missing Commit Metadata Fields by Year", fontsize=14)
        plt.xlabel("Publication Year")
        plt.ylabel("Missing Fields per Record")
        plt.grid(True, alpha=0.3)
        plt.savefig("temporal_missingness.png", bbox_inches="tight")
        plt.close()

    def _create_heatmap(self):
        """Create detailed field missingness heatmap"""
        heatmap_data = []
        for cat, fields in self.field_categories.items():
            for field in fields:
                heatmap_data.append(
                    {
                        "Category": cat,
                        "Field": field.split(".")[-1],
                        "Missing (%)": self.missing_pct[field],
                    }
                )

        df = pd.DataFrame(heatmap_data)
        pivot_df = df.pivot(index="Category", columns="Field", values="Missing (%)")

        plt.figure(figsize=(16, 8))
        sns.heatmap(
            pivot_df,
            annot=True,
            fmt=".1f",
            cmap="YlGnBu",
            cbar_kws={"label": "Missing Data (%)"},
        )
        plt.title("Detailed Field-Level Missingness Analysis", fontsize=14, pad=20)
        plt.xticks(rotation=45, ha="right")
        plt.savefig("field_missingness_heatmap.png", bbox_inches="tight")
        plt.close()

    def _create_score_radar(self):
        """Create radar chart of completeness scores"""
        categories = list(self.category_scores.keys())
        scores = list(self.category_scores.values())
        scores += scores[:1]  # Close the radar chart

        N = len(categories)
        angles = [n / float(N) * 2 * np.pi for n in range(N)]
        angles += angles[:1]

        plt.figure(figsize=(8, 8))
        ax = plt.subplot(polar=True)
        ax.plot(angles, scores, linewidth=1, linestyle="solid")
        ax.fill(angles, scores, "b", alpha=0.1)
        ax.set_theta_offset(np.pi / 2)
        ax.set_theta_direction(-1)
        plt.xticks(angles[:-1], categories, size=10)
        plt.yticks([20, 40, 60, 80], ["20%", "40%", "60%", "80%"], size=10)
        plt.ylim(0, 100)
        plt.title("Data Quality Radar Chart", size=14, y=1.1)
        plt.savefig("quality_radar.png", bbox_inches="tight")
        plt.close()

    def _compile_report(self):
        """Compile markdown report with analysis"""
        self.report_content = [
            "# Data Quality Assessment Report",
            "## Executive Summary",
            f"- **Total Records Analyzed**: {self.total_files:,}",
            f"- **Overall Completeness Score**: {self.overall_score:.1f}%",
            "### Key Completeness Scores:",
            *[
                f"- **{cat}**: {score:.1f}%"
                for cat, score in self.category_scores.items()
            ],
            "",
            "## Root Cause Analysis",
            *[
                f"### {cat}\n{textwrap.fill(cause, width=80)}"
                for cat, cause in self.root_causes.items()
            ],
            "",
            "## Visual Analysis",
            "### Data Completeness by Category",
            "![Completeness Categories](completeness_categories.png)",
            "",
            "### Temporal Missingness Pattern",
            (
                "![Temporal Analysis](temporal_missingness.png)"
                if self.temporal_data
                else ""
            ),
            "",
            "### Field-Level Missingness Heatmap",
            "![Field Missingness](field_missingness_heatmap.png)",
            "",
            "### Data Quality Radar Chart",
            "![Quality Radar](quality_radar.png)",
            "",
            "## Recommendations",
            "1. **Priority Enhancement**: Focus on Commit Metadata collection (most impactful)",
            "2. **Fallback Strategies**: Implement repository-level averages for author stats",
            "3. **Data Supplementation**: Use Archive.org for deleted repositories",
            "4. **Validation Pipeline**: Add automated completeness checks to collection workflow",
        ]

        with open("data_quality_report.md", "w") as f:
            f.write("\n".join([line for line in self.report_content if line]))

    def _nested_field_exists(self, data: dict, field_path: str) -> bool:
        """Check nested field existence"""
        keys = field_path.split(".")
        current = data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return False
        return True

    def _log_error(self, message: str):
        """Log errors to file"""
        with open("report_errors.log", "a") as f:
            f.write(f"{datetime.now().isoformat()}: {message}\n")


if __name__ == "__main__":
    print("Generating enhanced data quality report...")
    reporter = EnhancedDataReporter()
    reporter.generate_report()
    print("Report generation complete!")
    print("Output files:")
    print("- data_quality_report.md")
    print("- completeness_categories.png")
    print("- temporal_missingness.png")
    print("- field_missingness_heatmap.png")
    print("- quality_radar.png")
    print("- report_errors.log (if any errors occurred)")
