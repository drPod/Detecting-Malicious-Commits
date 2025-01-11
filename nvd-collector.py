import requests
import json
from datetime import datetime, timedelta
import time
import logging
from typing import Dict, List, Optional
import os
from urllib.parse import urlparse
from pathlib import Path


class NVDCollector:
    def __init__(self, api_key: str, data_dir: str = "nvd_data"):
        """
        Initialize the NVD data collector.

        Args:
            api_key: NVD API key for authenticated requests
            data_dir: Directory to store JSON files
        """
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"apiKey": api_key, "User-Agent": "NVDCollector/1.0"}

        # Create data directory if it doesn't exist
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        logging.basicConfig(
            level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
        )
        self.logger = logging.getLogger(__name__)

    def extract_github_info(self, references: List[Dict]) -> Dict:
        """Extract GitHub-related information from references."""
        github_data = {
            "repository": None,
            "fix_commit": None,
            "related_commits": [],
            "patch_url": None,
        }

        for ref in references:
            url = ref.get("url", "")
            if "github.com" in url:
                # Parse GitHub URL
                parsed = urlparse(url)
                path_parts = parsed.path.split("/")

                # Extract repository information
                if len(path_parts) >= 3:
                    github_data["repository"] = f"{path_parts[1]}/{path_parts[2]}"

                # Extract commit information
                if "commit" in path_parts:
                    commit_idx = path_parts.index("commit")
                    if len(path_parts) > commit_idx + 1:
                        commit_hash = path_parts[commit_idx + 1]
                        if not github_data["fix_commit"]:
                            github_data["fix_commit"] = commit_hash
                        github_data["related_commits"].append(commit_hash)

                # Extract patch URL
                if url.endswith(".patch"):
                    github_data["patch_url"] = url

        return github_data

    def process_vulnerability(self, cve_data: Dict) -> Dict:
        """Process raw CVE data into structured format."""
        vuln = cve_data.get("cve", {})

        # Extract metrics
        metrics = vuln.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})

        # Extract CWE ID - handle the new NVD API structure
        cwe_id = None
        weaknesses = vuln.get("weaknesses", [])
        if weaknesses and len(weaknesses) > 0:
            # Get the first weakness description
            weakness_desc = weaknesses[0].get("description", [])
            if weakness_desc:
                # Get the first description's CWE ID
                cwe_id = next(
                    (
                        desc.get("value")
                        for desc in weakness_desc
                        if desc.get("value", "").startswith("CWE-")
                    ),
                    None,
                )

        # Build vulnerability entry
        vulnerability_entry = {
            "cve_id": vuln.get("id"),
            "github_data": self.extract_github_info(vuln.get("references", [])),
            "vulnerability_details": {
                "cvss_score": cvss_v31.get("baseScore"),
                "cvss_vector": cvss_v31.get("vectorString"),
                "cwe_id": cwe_id,
                "description": vuln.get("descriptions", [{}])[0].get("value"),
                "attack_vector": cvss_v31.get("attackVector"),
                "attack_complexity": cvss_v31.get("attackComplexity"),
            },
            "temporal_data": {
                "published_date": vuln.get("published"),
                "last_modified": vuln.get("lastModified"),
                "fix_date": None,  # Will be populated later from GitHub
            },
            "references": [
                {
                    "url": ref.get("url"),
                    "source": ref.get("source"),
                    "tags": ref.get("tags", []),
                }
                for ref in vuln.get("references", [])
            ],
            "collection_metadata": {
                "collected_at": datetime.utcnow().isoformat(),
                "processing_status": "raw",
            },
        }

        return vulnerability_entry

    def save_vulnerability(self, vulnerability: Dict) -> None:
        """Save vulnerability data to a JSON file."""
        if vulnerability["github_data"]["repository"]:
            file_path = self.data_dir / f"{vulnerability['cve_id']}.json"
            with open(file_path, "w") as f:
                json.dump(vulnerability, f, indent=2)

    def load_existing_cves(self) -> set:
        """Load set of existing CVE IDs from saved files."""
        return {f.stem for f in self.data_dir.glob("*.json")}

    def fetch_vulnerabilities(
        self, start_date: Optional[str] = None, batch_size: int = 2000
    ) -> None:
        """
        Fetch vulnerabilities from NVD API with pagination.

        Args:
            start_date: Optional start date in format "YYYY-MM-DD"
            batch_size: Number of records to fetch per request
        """
        try:
            params = {"resultsPerPage": batch_size, "startIndex": 0}

            if start_date:
                params["pubStartDate"] = f"{start_date}T00:00:00.000"

            existing_cves = self.load_existing_cves()

            while True:
                self.logger.info(
                    f"Fetching vulnerabilities starting at index {params['startIndex']}"
                )

                response = requests.get(
                    self.base_url, headers=self.headers, params=params
                )
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                if not vulnerabilities:
                    break

                # Process and store vulnerabilities
                for vuln_data in vulnerabilities:
                    processed_vuln = self.process_vulnerability(vuln_data)

                    # Only save if it has GitHub data and we haven't processed it before
                    if (
                        processed_vuln["github_data"]["repository"]
                        and processed_vuln["cve_id"] not in existing_cves
                    ):
                        self.save_vulnerability(processed_vuln)
                        existing_cves.add(processed_vuln["cve_id"])

                # Update start index for next batch
                params["startIndex"] += batch_size

                # Respect API rate limits
                time.sleep(0.6)  # NVD API limit is 5 requests per second

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching vulnerabilities: {str(e)}")
            raise

    def get_vulnerability_stats(self) -> Dict:
        """Get statistics about collected vulnerabilities."""
        stats = {
            "total_vulnerabilities": 0,
            "unique_repositories": set(),
            "avg_cvss_score": 0,
            "vulnerabilities_by_year": {},
        }

        total_cvss = 0

        for file_path in self.data_dir.glob("*.json"):
            with open(file_path) as f:
                vuln = json.load(f)

                stats["total_vulnerabilities"] += 1
                stats["unique_repositories"].add(vuln["github_data"]["repository"])

                if vuln["vulnerability_details"]["cvss_score"]:
                    total_cvss += vuln["vulnerability_details"]["cvss_score"]

                year = vuln["temporal_data"]["published_date"][:4]
                stats["vulnerabilities_by_year"][year] = (
                    stats["vulnerabilities_by_year"].get(year, 0) + 1
                )

        if stats["total_vulnerabilities"] > 0:
            stats["avg_cvss_score"] = total_cvss / stats["total_vulnerabilities"]

        stats["unique_repositories"] = len(stats["unique_repositories"])

        return stats


if __name__ == "__main__":
    # Load configuration from environment variables
    api_key = os.getenv("NVD_API_KEY")

    if not api_key:
        raise ValueError("Please set NVD_API_KEY environment variable")

    collector = NVDCollector(api_key)

    # Fetch last 30 days of vulnerabilities
    # start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    # collector.fetch_vulnerabilities(start_date=start_date)
    collector.fetch_vulnerabilities()

    # Print statistics
    stats = collector.get_vulnerability_stats()
    print("\nCollection Statistics:")
    print(f"Total vulnerabilities: {stats['total_vulnerabilities']}")
    print(f"Unique repositories: {stats['unique_repositories']}")
    print(f"Average CVSS score: {stats['avg_cvss_score']:.2f}")
    print("\nVulnerabilities by year:")
    for year, count in sorted(stats["vulnerabilities_by_year"].items()):
        print(f"{year}: {count}")
