import os
import json
import logging
import subprocess
import traceback
from pathlib import Path
from typing import Optional

# 1. Configuration
NVD_DATA_DIR = Path("nvd_data")
REPOS_DIR = Path("repos")
OUTPUT_FILE = Path("cve_introducing_commits.json")

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("introducing_commit_finder.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def find_introducing_commit(
    repo_path: Path, fix_commit_hash: str, file_path: str
) -> Optional[str]:
    """
    Finds the introducing commit for a given file path using git log.

    Args:
        repo_path: Path to the git repository.
        fix_commit_hash: Hash of the fix commit.
        file_path: Path to the file within the repository.

    Returns:
        The hash of the introducing commit, or None if not found.
    """
    try:
        command = [
            "git",
            "log",
            "-L",
            f"1,<very_large_number>:{file_path}",
            "--reverse",
            "--format=%H",  # Only output commit hashes
            f"{fix_commit_hash}^..HEAD",  # From parent of fix commit to HEAD
            "--",
            file_path,
        ]
        process = subprocess.run(command, cwd=repo_path, capture_output=True, text=True)
        process.check_returncode()  # Raise exception for non-zero return codes
        output = process.stdout.strip()
        commits = output.splitlines()

        if not commits:
            logger.warning(
                f"No commit history found for file '{file_path}' in range for fix commit {fix_commit_hash}"
            )
            return None

        # The first commit in reverse chronological order is the introducing commit
        introducing_commit_hash = commits[0]
        return introducing_commit_hash

    except subprocess.CalledProcessError as e:
        logger.error(f"Git command failed for {file_path} in {repo_path}: {e}")
        logger.error(f"Stderr: {e.stderr}")
        return None
    except Exception as e:
        logger.error(
            f"Error finding introducing commit for {file_path} in {repo_path}: {e}"
        )
        logger.error(traceback.format_exc())
        return None


def main():
    """
    Main function to find vulnerability-introducing commits for CVEs.
    """
    cve_introducing_commits = {}
    logger.info("Starting introducing commit finder script.")

    for cve_file_path in NVD_DATA_DIR.glob("*.json"):
        try:
            with open(cve_file_path, "r") as f:
                cve_data = json.load(f)

            cve_id = cve_data.get("cve_id")
            github_data = cve_data.get("github_data", {})
            repository = github_data.get("repository")
            fix_commit = github_data.get("fix_commit")

            if not cve_id or not repository or not fix_commit:
                logger.warning(
                    f"Skipping {cve_file_path.name}: Missing CVE ID, repository, or fix commit."
                )
                continue

            repo_name_safe = repository.replace("/", "_")
            repo_path = REPOS_DIR / repo_name_safe

            if not repo_path.exists() or not (repo_path / ".git").exists():
                logger.warning(
                    f"Repository directory '{repo_path}' does not exist. Skipping CVE {cve_id}."
                )
                continue

            logger.info(
                f"Processing CVE: {cve_id}, Repository: {repository}, Fix Commit: {fix_commit}"
            )
            os.chdir(repo_path)  # Change working directory to repo path

            # Find changed files in fix commit
            diff_tree_command = [
                "git",
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                fix_commit,
            ]
            diff_tree_process = subprocess.run(
                diff_tree_command, capture_output=True, text=True
            )
            diff_tree_process.check_returncode()
            changed_files = diff_tree_process.stdout.strip().splitlines()

            introducing_commits_for_cve = {}
            for file_path in changed_files:
                introducing_commit_hash = find_introducing_commit(
                    repo_path, fix_commit, file_path
                )
                if introducing_commit_hash:
                    introducing_commits_for_cve[file_path] = introducing_commit_hash

            cve_introducing_commits[cve_id] = {
                "repository": repository,
                "fix_commit": fix_commit,
                "introducing_commits_for_cve": introducing_commits_for_cve,
            }

        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from {cve_file_path.name}. Skipping.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Git command failed for CVE file {cve_file_path.name}: {e}")
            logger.error(f"Stderr: {e.stderr}")
        except Exception as e:
            logger.error(f"Error processing CVE file {cve_file_path.name}: {e}")
            logger.error(traceback.format_exc())

    # Write results to output file
    try:
        with open(OUTPUT_FILE, "w") as outfile:
            json.dump(cve_introducing_commits, outfile, indent=4)
        logger.info(f"Successfully wrote CVE introducing commits to {OUTPUT_FILE}")
    except Exception as e:
        logger.error(f"Error writing to output file {OUTPUT_FILE}: {e}")
        logger.error(traceback.format_exc())

    logger.info("Introducing commit finder script completed.")


if __name__ == "__main__":
    main()
