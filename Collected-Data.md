# nvd_data stats

```json
vulnerability_entry = {
    "cve_id": "CVE-2023-XXXXX",
    "github_data": {
        "repository": "owner/repo",
        "fix_commit": "hash",
        "related_commits": ["hash1", "hash2"],
        "patch_url": "url"
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
        "fix_date": "timestamp"  # From GitHub commit
    },
    "references": [
        {
            "url": "string",
            "source": "string",
            "tags": ["patch", "exploit", "article"]
        }
    ]
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