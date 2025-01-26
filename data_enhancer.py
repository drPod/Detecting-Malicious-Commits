# data_enhancer.py
import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional
import time
from tqdm import tqdm
from dotenv import load_dotenv
from github_data_collector import GitHubDataCollector, TokenManager, load_github_tokens


class DataEnhancer(GitHubDataCollector):
    def __init__(self, token_manager: TokenManager, max_workers: int = 10):
        super().__init__(
            token_manager=token_manager,
            nvd_data_dir="nvd_data",
            repo_data_dir="repo_data",
            max_workers=max_workers,
        )
        self.processed_files = set()
        self._load_existing_data()

    def _load_existing_data(self):
        """Cache already processed files to avoid rework"""
        for f in self.nvd_data_dir.glob("*.json"):
            with open(f) as file:
                data = json.load(file)
                if data.get("github_data", {}).get("fix_commit_details"):
                    self.processed_files.add(f.name)

    def needs_processing(self, file_path: Path) -> bool:
        """Check if file needs enhancement"""
        if file_path.name in self.processed_files:
            return False

        try:
            with open(file_path) as f:
                data = json.load(f)
                # Check for missing critical fields
                if not data.get("github_data", {}).get("fix_commit_details"):
                    return True
                if not data.get("repository_context"):
                    return True
                return False
        except Exception:
            return True

    def enhance_file(self, file_path: Path) -> Optional[Dict]:
        """Process a single file with enhanced error handling"""
        try:
            if not self.needs_processing(file_path):
                return None

            with open(file_path) as f:
                vuln_data = json.load(f)

            # Check if repository data is missing
            if not vuln_data.get("repository_context"):
                owner, repo = vuln_data["github_data"]["repository"].split("/")
                repo_data = self.get_repository_data(owner, repo)
                if repo_data:
                    vuln_data["repository_context"] = repo_data

            # Check if commit details are missing
            if not vuln_data.get("github_data", {}).get("fix_commit_details"):
                commit_hash = vuln_data["github_data"]["fix_commit"]
                if commit_hash:
                    owner, repo = vuln_data["github_data"]["repository"].split("/")
                    commit_data = self.get_commit_data(owner, repo, commit_hash)
                    if commit_data:
                        vuln_data["github_data"]["fix_commit_details"] = commit_data
                        vuln_data["temporal_data"]["fix_date"] = commit_data[
                            "commit_date"
                        ]

            # Update processing status
            vuln_data["collection_metadata"]["processing_status"] = "enhanced"

            # Save updated data
            with open(file_path, "w") as f:
                json.dump(vuln_data, f, indent=2)

            return vuln_data

        except Exception as e:
            self.logger.error(f"Error enhancing {file_path.name}: {str(e)}")
            return None

    def run_enhancement(self):
        """Main enhancement loop with progress tracking"""
        files = list(self.nvd_data_dir.glob("*.json"))
        to_process = [f for f in files if self.needs_processing(f)]

        self.logger.info(f"Found {len(to_process)} files needing enhancement")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.enhance_file, f): f for f in to_process}

            with tqdm(total=len(futures), desc="Enhancing data") as pbar:
                for future in as_completed(futures):
                    file_path = futures[future]
                    try:
                        result = future.result()
                        if result:
                            self.processed_files.add(file_path.name)
                    except Exception as e:
                        self.logger.error(
                            f"Failed to process {file_path.name}: {str(e)}"
                        )
                    finally:
                        pbar.update(1)


def main():
    load_dotenv()
    tokens = load_github_tokens()
    print(f"Loaded {len(tokens)} GitHub tokens")

    token_manager = TokenManager(tokens)
    enhancer = DataEnhancer(
        token_manager=token_manager,
        max_workers=min(len(tokens) * 2, 20),  # More aggressive threading
    )

    enhancer.run_enhancement()
    print("\nEnhancement complete! Check logs for details.")


if __name__ == "__main__":
    main()
