# data_validator.py
import json
from pathlib import Path
from collections import defaultdict

REQUIRED_FIELDS = {
    # Top-level fields
    "cve_id": [],
    "github_data": [
        "repository",
        "fix_commit",
        "related_commits",
        "patch_url",
        "fix_commit_details",
    ],
    "vulnerability_details": [
        "cvss_score",
        "cvss_vector",
        "cwe_id",
        "description",
        "attack_vector",
        "attack_complexity",
    ],
    "temporal_data": ["published_date", "last_modified", "fix_date"],
    "references": [],
    "repository_context": [
        "name",
        "owner",
        "security_features",
        "commit_activity",
        "languages",
        "stars",
        "forks",
    ],
    "collection_metadata": ["collected_at", "processing_status"],
    # Nested fields
    "github_data.fix_commit_details": [
        "sha",
        "commit_date",
        "author",
        "commit_message",
        "stats",
        "file_patterns",
        "context",
    ],
    "github_data.fix_commit_details.author": ["login", "type", "stats"],
    "github_data.fix_commit_details.author.stats": [
        "total_commits",
        "average_weekly_commits",
        "total_additions",
        "total_deletions",
        "weeks_active",
    ],
    "github_data.fix_commit_details.commit_message": [
        "title",
        "length",
        "has_description",
        "references_issue",
    ],
    "github_data.fix_commit_details.stats": ["additions", "deletions", "total"],
    "github_data.fix_commit_details.file_patterns": [
        "security_files",
        "config_files",
        "dependency_files",
        "test_files",
        "unique_directories",
        "max_directory_depth",
    ],
    "github_data.fix_commit_details.context": ["surrounding_commits"],
    "repository_context.security_features": [
        "has_security_policy",
        "has_protected_branches",
        "has_wiki",
        "has_issues",
        "license",
    ],
    "repository_context.commit_activity": [
        "total_commits_last_year",
        "avg_commits_per_week",
        "days_active_last_year",
    ],
}


def check_field(data: dict, path: str) -> bool:
    """Check if a nested field exists"""
    keys = path.split(".")
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return False
    return True


def audit_data_quality(data_dir: str):
    missing_counts = defaultdict(int)
    field_coverage = defaultdict(list)
    total_files = 0

    for file_path in Path(data_dir).glob("*.json"):
        with open(file_path) as f:
            data = json.load(f)
            total_files += 1

            for category, fields in REQUIRED_FIELDS.items():
                if not fields:  # Handle root-level fields
                    if category not in data:
                        missing_counts[category] += 1
                    continue

                for field in fields:
                    full_path = (
                        f"{category}.{field}"
                        if "." not in category
                        else f"{category}.{field}"
                    )
                    exists = check_field(data, full_path)

                    if not exists:
                        missing_counts[full_path] += 1
                    field_coverage[full_path].append(exists)

    print(f"\nData Quality Audit Report ({total_files} files):")
    print("Missing Fields (Count and Percentage):")

    # Sort by most missing first
    sorted_missing = sorted(missing_counts.items(), key=lambda x: x[1], reverse=True)

    for field_path, count in sorted_missing:
        percentage = count / total_files * 100
        print(f"- {field_path}: {count} ({percentage:.1f}%)")

    # Calculate overall completeness
    total_fields = sum(len(fields) for fields in REQUIRED_FIELDS.values()) + len(
        REQUIRED_FIELDS
    )
    present_fields = total_fields * total_files - sum(missing_counts.values())
    overall_completeness = present_fields / (total_fields * total_files) * 100

    print(f"\nOverall Data Completeness: {overall_completeness:.1f}%")


if __name__ == "__main__":
    audit_data_quality("../../nvd_data")
