import subprocess
import json
import logging
from pathlib import Path
from typing import Optional, Dict
import traceback

# 1. Configuration
NVD_DATA_DIR = Path("nvd_data")
REPOS_DIR = Path("repos")
OUTPUT_DIR = Path("cve_introducing_commits")  # Changed to directory

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

# Create output directory if it doesn't exist
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def find_introducing_commit(
    repo_path: Path, fix_commit_hash: str, file_path: str
) -> Optional[str]:
    """
    Finds the commit that introduced the vulnerability for a specific file.

    Args:
        repo_path (Path): Path to the cloned git repository.
        fix_commit_hash (str): Hash of the commit that fixed the vulnerability.
        file_path (str): Path to the vulnerable file within the repository.

    Returns:
        Optional[str]: Hash of the introducing commit if found, otherwise None.
    """
    try:
        # Construct git blame command to find the introducing commit
        command = [
            "git",
            "blame",
            "--reverse",  # Reverse blame, find commits *after* a certain commit
            "--first-parent",  # Follow only the first parent commit upon seeing a merge
            fix_commit_hash
            + "^",  # Start blaming from the commit before the fix commit
            "--",
            file_path,
        ]
        process = subprocess.Popen(
            command, cwd=repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate(
            timeout=30
        )  # Increased timeout to 30 seconds

        if stderr:
            error_message = stderr.decode()
            if "fatal: no such path" in error_message:
                logger.warning(
                    f"File path '{file_path}' not found in repository at commit {fix_commit_hash}. It may have been introduced in the fix commit or later."
                )
                return (
                    None  # File not found, might be introduced in fix commit or later
                )
            elif "fatal: no commits found in range" in error_message:
                logger.warning(
                    f"No commits found before fix commit {fix_commit_hash} for file '{file_path}'. Vulnerability might be very old or the fix commit is the first commit."
                )
                return None  # No commits before fix commit, vulnerability might be very old
            else:
                logger.error(
                    f"Error during git blame for {file_path} at {fix_commit_hash}: {error_message}"
                )
                return None  # Git blame error

        # Parse the output to extract the earliest commit hash
        blame_output = stdout.decode().strip()
        if blame_output:
            # The first line of blame output contains commit hash
            introducing_commit_hash = blame_output.split()[0]
            return introducing_commit_hash
        else:
            logger.warning(
                f"No blame output for {file_path} in {repo_path} before {fix_commit_hash}. File might be introduced in fix commit."
            )
            return None  # No blame output, file might be introduced in fix commit

    except subprocess.TimeoutExpired:
        logger.error(
            f"Git blame command timed out for {file_path} in {repo_path} at {fix_commit_hash}."
        )
        return None
    except Exception as e:
        logger.error(
            f"Unexpected error during git blame for {file_path} in {repo_path} at {fix_commit_hash}: {e}"
        )
        return None


def process_cve_file(cve_file_path: Path):
    """
    Processes a single CVE JSON file to find introducing commits.

    Args:
        cve_file_path (Path): Path to the CVE JSON file.
    """
    try:
        with open(cve_file_path, "r") as f:
            cve_data = json.load(f)
            cve_id = cve_data["cve_id"]
            repository = cve_data["github_data"]["repository"]
            fix_commit = cve_data["github_data"]["fix_commit"]

            if not repository or not fix_commit:
                logger.warning(
                    f"Skipping {cve_id} due to missing repository or fix commit information."
                )
                return

            repo_path = REPOS_DIR / repository.replace("/", "_")
            if not repo_path.exists() or not (repo_path / ".git").exists():
                logger.error(
                    f"Repository path {repo_path} does not exist or is not a valid git repository. Skipping {cve_id}."
                )
                return

            introducing_commits_for_cve: Dict[str, Optional[str]] = {}

            # Iterate over all files in the fix commit
            commit_details = cve_data["github_data"].get("fix_commit_details", {})
            files_in_commit = commit_details.get("files", [])

            if not files_in_commit:
                logger.warning(
                    f"No files found in fix commit details for {cve_id}. Skipping file analysis."
                )
            else:
                logger.info(
                    f"Processing {len(files_in_commit)} files from fix commit for {cve_id} in {repository}"
                )
                for file_data in files_in_commit:
                    file_path = file_data["filename"]
                    introducing_commit_hash = find_introducing_commit(
                        repo_path, fix_commit, file_path
                    )
                    if introducing_commit_hash:
                        introducing_commits_for_cve[file_path] = introducing_commit_hash

            cve_result = {  # Structure for each CVE's output
                "repository": repository,
                "fix_commit": fix_commit,
                "introducing_commits_for_cve": introducing_commits_for_cve,
            }
            output_file_path = OUTPUT_DIR / f"{cve_id}.json"  # File path for each CVE
            with open(output_file_path, "w") as outfile:
                json.dump(
                    cve_result, outfile, indent=4
                )  # Write each CVE to its own file
            logger.info(
                f"Successfully wrote introducing commits for {cve_id} to {output_file_path}"
            )

    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from {cve_file_path.name}. Skipping.")
    except FileNotFoundError:
        logger.error(f"CVE data file not found: {cve_file_path}")
    except Exception as e:
        logger.error(f"Error processing CVE file {cve_file_path.name}: {e}")
        logger.error(traceback.format_exc())

    logger.info(
        f"Successfully wrote all CVE introducing commits to {OUTPUT_DIR}"
    )  # Summary log message updated
    logger.info("Introducing commit finder script completed.")


def main():
    """
    Main function to find vulnerability-introducing commits for CVEs.
    """
    # cve_introducing_commits = {} # No longer needed to store all in memory
    logger.info("Starting introducing commit finder script.")

    for cve_file_path in NVD_DATA_DIR.glob("*.json"):
        process_cve_file(cve_file_path)

    logger.info("Introducing commit finder script completed.")


if __name__ == "__main__":
    main()
