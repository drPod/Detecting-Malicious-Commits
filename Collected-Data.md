# nvd_data stats

```json
vulnerability_entry = {
    "cve_id": "CVE-2023-XXXXX",
    "github_data": {
        "repository": "owner/repo",
        "fix_commit": "hash",
        "related_commits": ["hash1", "hash2"],
        "patch_url": "url",
        "fix_commit_details": {
            "sha": "commit_hash",
            "commit_date": "ISO date",
            "author": {
                "login": "username",
                "type": "User/Organization",
                "stats": {
                    "total_commits": int,
                    "average_weekly_commits": float,
                    "total_additions": int,
                    "total_deletions": int,
                    "weeks_active": int
                }
            },
            "commit_message": {
                "title": "commit title",
                "length": int,
                "has_description": bool,
                "references_issue": bool
            },
            "stats": {
                "additions": int,
                "deletions": int,
                "total": int
            },
            "file_patterns": {
                "security_files": int,
                "config_files": int,
                "dependency_files": int,
                "test_files": int,
                "unique_directories": int,
                "max_directory_depth": int
            },
            "context": {
                "surrounding_commits": [
                    {
                        "sha": "hash",
                        "date": "ISO date",
                        "author_login": "username"
                    }
                ]
            }
        }
    },
    "vulnerability_details": {
        "cvss_score": float,
        "cvss_vector": "string",
        "cwe_id": "CWE-XXX",
        "description": "text",
        "attack_vector": "string",
        "attack_complexity": "string"
    },
    "temporal_data": {
        "published_date": "timestamp",
        "last_modified": "timestamp",
        "fix_date": "timestamp"  # Populated from GitHub commit
    },
    "references": [
        {
            "url": "string",
            "source": "string",
            "tags": ["patch", "exploit", "article"]
        }
    ],
    "repository_context": {
        "name": "repo-name",
        "owner": "owner",
        "security_features": {
            "has_security_policy": bool,
            "has_protected_branches": bool,
            "has_wiki": bool,
            "has_issues": bool,
            "license": "string"
        },
        "commit_activity": {
            "total_commits_last_year": int,
            "avg_commits_per_week": float,
            "days_active_last_year": int
        },
        "languages": {"Language": bytes},
        "stars": int,
        "forks": int
    },
    "collection_metadata": {
        "collected_at": "ISO timestamp",
        "processing_status": "raw|enhanced"
    }
}
```

Total vulnerabilities: 46704

Unique repositories: 14755

Average CVSS score: 5.52

Vulnerabilities by year:

- 1999: 1
- 2000: 1
- 2004: 1
- 2006: 2
- 2007: 1
- 2008: 3
- 2009: 10
- 2010: 17
- 2011: 47
- 2012: 255
- 2013: 323
- 2014: 517
- 2015: 323
- 2016: 630
- 2017: 2839
- 2018: 4121
- 2019: 3189
- 2020: 3030
- 2021: 4815
- 2022: 8576
- 2023: 8280
- 2024: 9433
- 2025: 290
