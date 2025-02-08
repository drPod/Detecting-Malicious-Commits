import subprocess
import json
import logging
from pathlib import Path
from typing import Optional, Dict, List
import traceback
import concurrent.futures
import requests
from github_data_collector import TokenManager, load_github_tokens
import time

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

def _github_request(token_manager: TokenManager, url: str) -> Optional[dict]:
    """
    Make a rate-limited request to GitHub API using TokenManager.

    Args:
        token_manager: Instance of TokenManager for handling tokens.
        url: The GitHub API URL to request.

    Returns:
        dict: JSON response from GitHub API, or None if error.
    """
    while True:
        token = token_manager.get_available_token()
        headers = {
            "Authorization": f"token {token.key}",
            "Accept": "application/vnd.github.v3+json",
        }
        try:
            response = requests.get(url, headers=headers)
            token_manager.update_token_limits(token, response.headers)

            if response.status_code == 404:
                return None # Handle 404 as None, not an error
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            return response.json()

        except requests.exceptions.RequestException as e:
            if response.status_code == 403 and "rate limit exceeded" in response.text.lower():
                logger.warning(f"GitHub API rate limit exceeded. Retrying after waiting.")
                # TokenManager handles waiting, just retry
                continue
            else:
                logger.error(f"GitHub API request failed for {url}: {e}")
                return None # Return None on error
        except Exception as e:
            logger.error(f"Unexpected error during GitHub API request for {url}: {e}")
            return None # Return None on unexpected error

def get_commit_files_from_api(
    token_manager: TokenManager, owner: str, repo: str, commit_sha: str
) -> Optional[List[str]]:
    """
    Fetches the list of files changed in a commit from GitHub API.

    Args:
        token_manager: TokenManager instance.
        owner: Repository owner.
        repo: Repository name.
        commit_sha: Commit SHA.

    Returns:
        Optional[List[str]]: List of file paths changed in the commit, or None if API error.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
    commit_data = _github_request(token_manager, url)
    if commit_data and "files" in commit_
        return [file_data["filename"] for file_data in commit_data["files"]]
    return None

def find_introducing_commit(
    repo_path: Path, fix_commit_hash: str, file_path: str, cve_id: str
) -> Optional[str]:
    """
    Finds the commit that introduced the vulnerability for a specific file.

    Args:
        repo_path (Path): Path to the cloned git repository.
        fix_commit_hash (str): Hash of the commit that fixed the vulnerability.
        file_path (str): Path to the vulnerable file within the repository.
        cve_id (str): CVE ID being processed, for logging purposes.

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
                    f"{cve_id}: File path '{file_path}' not found in repository at commit {fix_commit_hash}. It may have been introduced in the fix commit or later."
                )
                return (
                    None  # File not found, might be introduced in fix commit or later
                )
            elif "fatal: no commits found in range" in error_message:
                logger.warning( # More specific warning message
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
                f"{cve_id}: No blame output for {file_path} in {repo_path} before {fix_commit_hash}. File might be introduced in fix commit."
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


def process_cve_file(cve_file_path: Path, token_manager: TokenManager) -> None: # Explicit return type
    """
    Processes a single CVE JSON file to find introducing commits.

    Args:
        cve_file_path (Path): Path to the CVE JSON file.
        token_manager: TokenManager instance for GitHub API requests.
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

            owner, repo = repository.split("/")
            changed_files = get_commit_files_from_api(token_manager, owner, repo, fix_commit)
            if changed_files is None:
                logger.warning(f"{cve_id}: Could not fetch changed files from GitHub API for commit {fix_commit}.")
                return # Skip to next CVE if we can't get file list

            if not changed_files:
                logger.warning(
                    f"No files found in fix commit details for {cve_id} from GitHub API. Skipping file analysis."
                )
            else:
                logger.debug( # Changed to debug as this can be verbose
                    f"{cve_id}: Processing {len(changed_files)} files from fix commit in {repository}"
                )
                for file_path in changed_files:
                    introducing_commit_hash = find_introducing_commit(
                        repo_path, fix_commit, file_path, cve_id
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


def main():
    """
    Main function to find vulnerability-introducing commits for CVEs.
    """
    # cve_introducing_commits = {} # No longer needed to store all in memory
    logger.info("Starting introducing commit finder script.")
    start_time = time.time() # Start timer

    # Load GitHub tokens
    try:
        tokens = load_github_tokens()
        logger.info(f"Loaded {len(tokens)} GitHub tokens for API requests.")
        token_manager = TokenManager(tokens)
    except ValueError as e:
        logger.error(f"Failed to load GitHub tokens: {e}")
        logger.error("Ensure you have set up GitHub tokens in .env file as GITHUB_TOKEN_1, GITHUB_TOKEN_2, etc.")
        return # Exit if no tokens are loaded

    cve_files = list(NVD_DATA_DIR.glob("*.json")) # Get list of files
    logger.info(f"Found {len(cve_files)} CVE files to process.") # Log number of files

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor: # Parallel processing
        executor.map(lambda file_path: process_cve_file(file_path, token_manager), cve_files) # Use executor map for parallel processing

    end_time = time.time() # End timer
    duration = end_time - start_time
    minutes = int(duration // 60)
    seconds = duration % 60
    logger.info(f"Introducing commit finder script completed in {minutes} minutes and {seconds:.2f} seconds.")

    logger.info(
        f"Successfully wrote all CVE introducing commits to {OUTPUT_DIR}"
    )  # Summary log message updated


    # Summary log message updated - moved here to be after all files are processed
    logger.info("Introducing commit finder script completed.")


if __name__ == "__main__":
    main()
