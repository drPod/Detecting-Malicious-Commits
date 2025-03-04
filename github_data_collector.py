import os
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import pandas as pd
from collections import deque
from dotenv import load_dotenv
import threading
from dataclasses import dataclass
from time import time, sleep


@dataclass
class Token:
    key: str
    last_used: float = 0
    requests_remaining: int = 5000
    reset_time: float = time() + 3600
    lock: threading.Lock = threading.Lock()


class TokenManager:
    def __init__(self, tokens: List[str]):
        self.tokens = deque([Token(key=token) for token in tokens])
        self.lock = threading.Lock()

    def get_available_token(self) -> Token:
        while True:
            with self.lock:
                # Rotate to try each token
                for _ in range(len(self.tokens)):
                    token = self.tokens[0]
                    current_time = time()

                    # Check if token is ready for use
                    with token.lock:
                        if current_time > token.reset_time:
                            # Reset quota if reset_time has passed
                            token.requests_remaining = 5000
                            token.reset_time = current_time + 3600

                        if (
                            token.requests_remaining > 0
                            and current_time - token.last_used >= 1.0
                        ):
                            # Token is available
                            token.last_used = current_time
                            token.requests_remaining -= 1
                            self.tokens.rotate(
                                -1
                            )  # Move to next token for next request
                            return token

                    self.tokens.rotate(-1)

                # If no token is immediately available, wait a bit
                min_wait = min(
                    token.last_used + 1.0 - current_time for token in self.tokens
                )
                if min_wait > 0:
                    sleep(min_wait)

    def update_token_limits(self, token: Token, headers: Dict):
        """Update token rate limits based on GitHub API response headers"""
        with token.lock:
            token.requests_remaining = int(
                headers.get("X-RateLimit-Remaining", token.requests_remaining)
            )
            token.reset_time = float(headers.get("X-RateLimit-Reset", token.reset_time))


class GitHubDataCollector:
    def __init__(
        self,
        token_manager: TokenManager,
        nvd_data_dir: str = "nvd_data",
        repo_data_dir: str = "repo_data",
        max_workers: int = 5,
    ):
        self.token_manager = token_manager
        self.nvd_data_dir = Path(nvd_data_dir)
        self.repo_data_dir = Path(repo_data_dir)
        self.repo_data_dir.mkdir(parents=True, exist_ok=True)
        self.max_workers = max_workers

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            filename="github_collector.log",
        )
        self.logger = logging.getLogger(__name__)

        # Cache for repository data
        self.repo_cache = {}
        self.repo_cache_lock = threading.Lock()

    def _github_request(self, url: str) -> dict:
        """Make a rate-limited request to GitHub API using token rotation"""
        while True:
            token = self.token_manager.get_available_token()

            headers = {
                "Authorization": f"token {token.key}",
                "Accept": "application/vnd.github.v3+json",
            }

            try:
                response = requests.get(url, headers=headers)
                self.token_manager.update_token_limits(token, response.headers)

                if response.status_code == 404:
                    return None
                response.raise_for_status()
                return response.json()

            except requests.exceptions.RequestException as e:
                if (
                    response.status_code == 403
                    and "rate limit exceeded" in response.text.lower()
                ):
                    # Rate limit exceeded, token will be skipped in next rotation
                    with token.lock:
                        token.requests_remaining = 0
                        continue
                raise

    def get_author_stats(
        self, owner: str, repo: str, author_login: str
    ) -> Optional[Dict]:
        """Get author's contribution statistics for the repository"""
        if not author_login:
            return None

        try:
            # Get author's contributions in last year
            url = f"https://api.github.com/repos/{owner}/{repo}/stats/contributors"
            contributors_data = self._github_request(url)

            if not contributors_data:
                return None

            author_stats = next(
                (
                    c
                    for c in contributors_data
                    if c.get("author", {}).get("login") == author_login
                ),
                None,
            )

            if not author_stats:
                return None

            # Calculate contribution patterns
            weekly_commits = author_stats.get("weeks", [])
            total_commits = sum(week.get("c", 0) for week in weekly_commits)
            commit_frequency = (
                total_commits / len(weekly_commits) if weekly_commits else 0
            )

            return {
                "total_commits": total_commits,
                "average_weekly_commits": commit_frequency,
                "total_additions": sum(week.get("a", 0) for week in weekly_commits),
                "total_deletions": sum(week.get("d", 0) for week in weekly_commits),
                "weeks_active": len([w for w in weekly_commits if w.get("c", 0) > 0]),
            }

        except Exception as e:
            self.logger.error(
                f"Error fetching author stats for {author_login}: {str(e)}"
            )
            return None

    def get_commit_data(
        self, owner: str, repo: str, commit_hash: str
    ) -> Optional[Dict]:
        """Fetch detailed commit data from GitHub"""
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_hash}"
            commit_data = self._github_request(url)

            if not commit_data:
                return None

            # Get surrounding commits for context
            url = f"https://api.github.com/repos/{owner}/{repo}/commits"
            params = {
                "sha": commit_hash,
                "per_page": 5,  # Get 2 commits before and after
            }
            surrounding_commits = self._github_request(url)

            # Extract the author login
            author_login = commit_data.get("author", {}).get("login")

            # Get author stats if available
            author_stats = self.get_author_stats(owner, repo, author_login)

            # Analyze file patterns
            files = commit_data.get("files", [])
            file_patterns = {
                "security_files": len(
                    [
                        f
                        for f in files
                        if any(
                            pattern in f["filename"].lower()
                            for pattern in [
                                "security",
                                "auth",
                                "crypto",
                                "password",
                                "secret",
                                "key",
                            ]
                        )
                    ]
                ),
                "config_files": len(
                    [
                        f
                        for f in files
                        if any(
                            pattern in f["filename"].lower()
                            for pattern in [
                                "config",
                                "settings",
                                ".env",
                                ".ini",
                                ".yml",
                                ".json",
                            ]
                        )
                    ]
                ),
                "dependency_files": len(
                    [
                        f
                        for f in files
                        if any(
                            pattern in f["filename"].lower()
                            for pattern in [
                                "requirements.txt",
                                "package.json",
                                "gemfile",
                                "cargo.toml",
                            ]
                        )
                    ]
                ),
                "test_files": len(
                    [f for f in files if "test" in f["filename"].lower()]
                ),
                "unique_directories": len(
                    set(str(Path(f["filename"]).parent) for f in files)
                ),
                "max_directory_depth": (
                    max(len(Path(f["filename"]).parts) - 1 for f in files)
                    if files
                    else 0
                ),
            }

            return {
                "sha": commit_hash,
                "commit_date": commit_data["commit"]["author"]["date"],
                "author": {
                    "login": author_login,
                    "type": commit_data.get("author", {}).get("type"),
                    "stats": author_stats,
                },
                "commit_message": {
                    "title": commit_data["commit"]["message"].split("\n")[0],
                    "length": len(commit_data["commit"]["message"]),
                    "has_description": len(commit_data["commit"]["message"].split("\n"))
                    > 1,
                    "references_issue": any(
                        ref in commit_data["commit"]["message"].lower()
                        for ref in ["fix", "close", "resolve", "issue", "#"]
                    ),
                },
                "stats": commit_data.get("stats", {}),
                "files": [
                    {
                        "filename": f["filename"],
                        "status": f["status"],
                        "additions": f["additions"],
                        "deletions": f["deletions"],
                        "patch": f.get("patch"),
                    }
                    for f in commit_data.get("files", [])
                ],
                "file_patterns": file_patterns,
                "context": {
                    "surrounding_commits": [
                        {
                            "sha": c["sha"],
                            "date": c["commit"]["author"]["date"],
                            "author_login": c.get("author", {}).get("login"),
                        }
                        for c in (surrounding_commits or [])[:5]
                    ]
                },
            }
        except Exception as e:
            self.logger.error(f"Error fetching commit {commit_hash}: {str(e)}")
            return None

    def get_repository_data(self, owner: str, repo: str) -> Optional[Dict]:
        """Fetch repository metadata and commit history"""
        repo_key = f"{owner}/{repo}"

        if repo_key in self.repo_cache:
            return self.repo_cache[repo_key]

        try:
            # Get repository metadata
            url = f"https://api.github.com/repos/{owner}/{repo}"
            repo_data = self._github_request(url)

            if not repo_data:
                return None

            # Get security policy
            security_url = (
                f"https://api.github.com/repos/{owner}/{repo}/security/policy"
            )
            security_data = self._github_request(security_url)

            # Get branch protection rules
            branches_url = f"https://api.github.com/repos/{owner}/{repo}/branches"
            branches_data = self._github_request(branches_url)

            # Get commit frequency stats
            stats_url = (
                f"https://api.github.com/repos/{owner}/{repo}/stats/commit_activity"
            )
            commit_stats = self._github_request(stats_url)

            # Get language statistics
            languages_url = f"https://api.github.com/repos/{owner}/{repo}/languages"
            languages_data = self._github_request(languages_url)

            processed_data = {
                "name": repo_data["name"],
                "owner": owner,
                "created_at": repo_data["created_at"],
                "updated_at": repo_data["updated_at"],
                "pushed_at": repo_data["pushed_at"],
                "size": repo_data["size"],
                "stars": repo_data["stargazers_count"],
                "forks": repo_data["forks_count"],
                "open_issues": repo_data["open_issues_count"],
                "watchers": repo_data["watchers_count"],
                "has_security_policy": bool(security_data),
                "default_branch": repo_data["default_branch"],
                "protected_branches": [
                    branch["name"]
                    for branch in branches_data or []
                    if branch.get("protected", False)
                ],
                "languages": languages_data,
                "commit_activity": {
                    "total_commits_last_year": sum(
                        week.get("total", 0) for week in (commit_stats or [])
                    ),
                    "avg_commits_per_week": (
                        sum(week.get("total", 0) for week in (commit_stats or [])) / 52
                        if commit_stats
                        else 0
                    ),
                    "days_active_last_year": (
                        sum(
                            1
                            for week in (commit_stats or [])
                            for day in week.get("days", [])
                            if day > 0
                        )
                        if commit_stats
                        else 0
                    ),
                },
                "security_features": {
                    "has_security_policy": bool(security_data),
                    "has_protected_branches": bool(
                        any(b.get("protected", False) for b in (branches_data or []))
                    ),
                    "has_wiki": repo_data.get("has_wiki", False),
                    "has_issues": repo_data.get("has_issues", False),
                    "allow_forking": repo_data.get("allow_forking", True),
                    "is_template": repo_data.get("is_template", False),
                    "license": repo_data.get("license", {}).get("key"),
                },
                "collected_at": datetime.utcnow().isoformat(),
            }

            self.repo_cache[repo_key] = processed_data
            return processed_data

        except Exception as e:
            self.logger.error(f"Error fetching repository {repo_key}: {str(e)}")
            return None

    def process_vulnerability_file(self, file_path: Path) -> Dict:
        """Process a single vulnerability JSON file"""
        try:
            with open(file_path) as f:
                vuln_data = json.load(f)

            if not vuln_data["github_data"]["repository"]:
                return None

            owner, repo = vuln_data["github_data"]["repository"].split("/")

            # Get repository data
            repo_data = self.get_repository_data(owner, repo)
            if not repo_data:
                return None

            # Get commit data
            fix_commit = vuln_data["github_data"]["fix_commit"]
            if fix_commit:
                commit_data = self.get_commit_data(owner, repo, fix_commit)
                if commit_data:
                    vuln_data["github_data"]["fix_commit_details"] = commit_data
                    vuln_data["temporal_data"]["fix_date"] = commit_data["commit_date"]

                    # Add patch URL if missing
                    if not vuln_data["github_data"]["patch_url"]:
                        vuln_data["github_data"][
                            "patch_url"
                        ] = f"https://github.com/{owner}/{repo}/commit/{fix_commit}.patch"

            # Update repository context
            vuln_data["repository_context"] = repo_data

            return vuln_data

        except Exception as e:
            self.logger.error(f"Error processing {file_path}: {str(e)}")
            return None

    def save_repository_data(self, repository: str, data: Dict):
        """Save repository data to a separate JSON file"""
        file_path = self.repo_data_dir / f"{repository.replace('/', '_')}.json"
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)

    def update_vulnerability_files(self):
        """Update all vulnerability files with additional GitHub data"""
        vuln_files = list(self.nvd_data_dir.glob("*.json"))

        self.logger.info(f"Processing {len(vuln_files)} vulnerability files")

        # Process files in parallel with progress bar
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self.process_vulnerability_file, file_path): file_path
                for file_path in vuln_files
            }

            # Process completed tasks with progress bar
            for future in tqdm(
                as_completed(future_to_file),
                total=len(vuln_files),
                desc="Processing vulnerabilities",
            ):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    if result:
                        # Save updated vulnerability data
                        with open(file_path, "w") as f:
                            json.dump(result, f, indent=2)

                        # Save repository data separately
                        if result["github_data"]["repository"]:
                            self.save_repository_data(
                                result["github_data"]["repository"],
                                result["repository_context"],
                            )

                except Exception as e:
                    self.logger.error(f"Error saving results for {file_path}: {str(e)}")


def load_github_tokens() -> List[str]:
    """Load GitHub tokens from .env file"""
    load_dotenv()
    tokens = []
    i = 1
    while True:
        token = os.getenv(f"GITHUB_TOKEN_{i}")
        if token:
            tokens.append(token)
            i += 1
        else:
            break

    if not tokens:
        raise ValueError("No GitHub tokens found in .env file")

    return tokens


def main():
    # Load GitHub tokens from .env
    tokens = load_github_tokens()
    print(f"Loaded {len(tokens)} GitHub tokens")

    # Initialize token manager and collector
    token_manager = TokenManager(tokens)
    collector = GitHubDataCollector(
        token_manager=token_manager,
        nvd_data_dir="nvd_data",
        repo_data_dir="repo_data",
        max_workers=min(
            len(tokens) * 2, 10
        ),  # Scale workers with tokens, but cap at 10
    )

    # Run collection
    collector.update_vulnerability_files()

    # Print summary statistics
    print("\nCollection completed!")
    print(f"See github_collector.log for detailed logging information")


if __name__ == "__main__":
    main()
