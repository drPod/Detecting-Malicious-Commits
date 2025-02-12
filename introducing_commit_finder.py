# This script uses the patches/ directory to find vulnerability introducing commits for each CVE.
import os
import re
from pathlib import Path
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from io import StringIO
from unidiff import PatchSet  # Import PatchSet from unidiff
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

import subprocess  # For running git blame

# --- Configuration ---
# Directories and files - now configurable via environment variables with defaults
PATCHES_DIR = Path(
    os.environ.get("PATCHES_DIR", "patches")
)  # Directory containing patch files
REPOS_DIR = Path(os.environ.get("REPOS_DIR", "repos"))
NVD_DATA_DIR = Path(
    os.environ.get("NVD_DATA_DIR", "nvd_data")
)  # Add NVD data directory
LOG_FILE = Path(os.environ.get("LOG_FILE", "introducing_commit_finder.log"))
OUTPUT_FILE = Path(
    os.environ.get("OUTPUT_FILE", "vulnerable_code_snippets.json")
)  # Output JSON file for results

# Script settings
LOG_LEVEL = logging.DEBUG  # Set default log level
CONTEXT_LINES_BEFORE = 2  # Number of context lines before vulnerable line
CONTEXT_LINES_AFTER = 3  # Number of context lines after vulnerable line
MAX_WORKERS = 12  # Number of threads for parallel processing


# Setup logging
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="w"),  # mode='w' to clear log on start
        logging.StreamHandler(),
    ],
)

logger = logging.getLogger(__name__)
logger.info(f"Script starting at {datetime.now().isoformat()}")
logger.info(f"Log file: {LOG_FILE.absolute()}")
logger.info(f"NVD data directory: {NVD_DATA_DIR.absolute()}")
logger.info(f"Patches directory: {PATCHES_DIR.absolute()}")
logger.info(f"Repository directory: {REPOS_DIR.absolute()}")
logger.info(f"Output file: {OUTPUT_FILE.absolute()}")


STATE_FILE = Path("commit_finder_state.json")  # State file for resuming
PROCESSED_PATCHES = set()  # Keep track of processed patches in memory
MAX_WORKERS = 10  # Number of threads for parallel processing


def load_state():
    """Load processed patches state from JSON file."""
    global PROCESSED_PATCHES
    if STATE_FILE.exists():
        try:
            with open(STATE_FILE, "r") as f:
                PROCESSED_PATCHES = set(json.load(f))
            logger.info(
                f"Loaded state for {len(PROCESSED_PATCHES)} patches from {STATE_FILE}"
            )
        except FileNotFoundError:
            logger.warning(
                f"State file not found at {STATE_FILE}, starting from scratch."
            )
        except json.JSONDecodeError as e:
            logger.error(
                f"Error decoding JSON from state file {STATE_FILE}: {e}. Starting from scratch."
            )


def save_state():
    """Save processed patches state to JSON file."""
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(PROCESSED_PATCHES), f)
        logger.info(f"Saved state for {len(PROCESSED_PATCHES)} patches to {STATE_FILE}")
    except Exception as e:
        logger.error(f"Error saving state to {STATE_FILE}: {e}")


def load_cve_data(cve_id: str) -> Optional[Dict[str, Any]]:
    """Load CVE data from JSON file."""
    cve_file = NVD_DATA_DIR / f"{cve_id}.json"
    if not cve_file.exists():
        logger.warning(
            f"CVE data file not found: {cve_file.absolute()}"
        )  # Log absolute path
        return None
    try:
        with open(cve_file, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(
            f"Error decoding JSON from {cve_file.absolute()}: {e}"
        )  # Log absolute path and error
        return None


def reset_repo_to_before_cve_date(repo_path: Path, cve_data: Dict[str, Any]) -> bool:
    """Resets the git repository to the commit before the CVE publication date."""
    cve_published_date_str = cve_data.get("temporal_data", {}).get("published_date")
    if not cve_published_date_str:
        logger.warning(f"CVE published date not found in data.")
        return False

    try:
        cve_published_date = datetime.strptime(
            cve_published_date_str, "%Y-%m-%dT%H:%M:%S.%f"
        )
        date_str_for_git = cve_published_date.strftime("%Y-%m-%d %H:%M:%S")

        # --- Branch detection logic ---
        default_branch = "main"  # Default branch
        try:
            command_symbolic_ref = [
                "/usr/bin/git",
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
            ]
            logger.debug(
                f"Executing git symbolic-ref command: {' '.join(command_symbolic_ref)} in {repo_path}"
            )  # Debug log
            process_symbolic_ref = subprocess.Popen(
                command_symbolic_ref,
                cwd=repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_symbolic_ref, stderr_symbolic_ref = process_symbolic_ref.communicate(
                timeout=30
            )
            if process_symbolic_ref.returncode != 0:
                error_message = stderr_symbolic_ref.decode("utf-8", errors="replace")
                logger.warning(
                    f"Git symbolic-ref failed with return code {process_symbolic_ref.returncode}: {error_message}, using fallback branch 'main'."
                )
                default_branch = "main"  # Hardcoded fallback branch
            else:
                remote_ref = stdout_symbolic_ref.decode("utf-8").strip()
                default_branch = remote_ref.split("/")[-1]  # Extract branch name
                logger.debug(
                    f"Detected default branch: {default_branch} from symbolic-ref"
                )
        except Exception as e:
            logger.warning(
                f"Error detecting default branch using symbolic-ref: {e}, using fallback branch 'main'."
            )
        # --- End branch detection logic ---

        # Find commit before CVE publication date
        command_rev_list = [
            "/usr/bin/git",
            "rev-list",
            f"--before='{date_str_for_git}'",
            "--max-count=1",
            default_branch,  # Use detected default branch here
        ]
        logger.debug(
            f"Executing git rev-list command: {' '.join(command_rev_list)} in {repo_path} using branch '{default_branch}'"
        )
        process_rev_list = subprocess.Popen(
            command_rev_list,
            cwd=repo_path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout_rev_list, stderr_rev_list = process_rev_list.communicate(timeout=30)

        if process_rev_list.returncode != 0:
            error_message = stderr_rev_list.decode("utf-8", errors="replace")
            logger.error(
                f"Git rev-list error with return code {process_rev_list.returncode}: {error_message}"
            )
            return False

        commit_hash = stdout_rev_list.decode("utf-8").strip()
        if not commit_hash:
            logger.warning(
                f"No commit found before CVE publication date: {date_str_for_git} on branch '{default_branch}'"
            )
            return False

        # Reset repository to the found commit
        command_reset = ["/usr/bin/git", "reset", "--hard", commit_hash]
        logger.debug(
            f"Executing git reset command: {' '.join(command_reset)} in {repo_path}"
        )
        process_reset = subprocess.Popen(
            command_reset, cwd=repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout_reset, stderr_reset = process_reset.communicate(timeout=30)

        if process_reset.returncode != 0:
            error_message = stderr_reset.decode("utf-8", errors="replace")
            logger.error(
                f"Git reset error with return code {process_reset.returncode}: {error_message}"
            )
            return False

        logger.info(
            f"Repository reset to commit {commit_hash} (before CVE publication date) on branch '{default_branch}'."
        )
        return True

    except subprocess.TimeoutExpired:
        logger.error("Git command timed out during repository reset.")
        return False
    except FileNotFoundError:
        logger.error("Git command not found. Is Git installed and in PATH?")
        return False
    except ValueError as e:
        logger.error(f"Error parsing CVE published date: {e}")
        return False
    except Exception as e:
        logger.error(f"Error resetting repository: {e}")
        return False


def extract_repo_name_from_patch_path(patch_file_path: Path) -> Optional[str]:
    """Extracts repository name from the patch file path."""
    try:
        repo_name_from_patch = patch_file_path.name.replace(
            f"{patch_file_path.name.split('_')[0]}_", ""
        ).replace(".patch", "")
        if not repo_name_from_patch:
            raise ValueError("Extracted repository name is empty.")
        return repo_name_from_patch
    except Exception as e:
        logger.error(
            f"Error extracting repo name from patch file path {patch_file_path}: {e}"
        )
        return None


def analyze_patch_file(patch_file_path: Path):  # Removed token_manager parameter
    """
    Analyzes a patch file to identify vulnerable code snippets and generate git blame commands.
    """
    vulnerable_snippets: List[Dict[str, Any]] = []
    repo_path = None
    repo_name_from_patch = None
    file_path_in_repo = None
    patch_content_str = ""
    cve_id = patch_file_path.name.split("_")[0]
    cve_data = load_cve_data(cve_id)
    cwe_id = (
        cve_data.get("vulnerability_details", {}).get("cwe_id") if cve_data else None
    )

    logger.info(f"Analyzing patch file: {patch_file_path.name}")

    if patch_file_path.stat().st_size == 0:  # Check for empty patch file
        logger.warning(f"Patch file {patch_file_path.name} is empty. Skipping.")
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "repo_name_from_patch": None,
            "file_path_in_repo": None,
        }

    # Read patch file content
    try:
        with open(patch_file_path, "r") as f:
            patch_content_str = f.read()
    except FileNotFoundError as e:
        logger.error(
            f"Patch file not found: {patch_file_path.absolute()}: {e}"
        )  # Log absolute path
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "repo_name_from_patch": None,
            "file_path_in_repo": None,
        }

    # Extract repo name from patch file name
    repo_name_from_patch = extract_repo_name_from_patch_path(patch_file_path)
    if repo_name_from_patch:
        repo = repo_name_from_patch  # Use extracted repo name
        repo_path = REPOS_DIR / repo_name_from_patch
    else:
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "repo_name_from_patch": None,
            "file_path_in_repo": None,
        }

    # --- On-demand cloning ---
    if not repo_path.exists() or not (repo_path / ".git").exists():
        logger.warning(
            f"Working repository directory does not exist: {repo_path.absolute()}. Expecting it to be cloned externally."  # Log absolute path
        )
    # --- End on-demand cloning ---

    # Reset repository to commit before CVE publication date
    if (
        repo_path.exists()
        and repo_path.is_dir()
        and cve_data
        and (repo_path / ".git").exists()
    ):  # Check for .git directory
        if not reset_repo_to_before_cve_date(repo_path, cve_data):
            logger.warning(
                f"Failed to reset repository {repo_name_from_patch} for CVE {cve_id}. Analysis might be inaccurate."
            )
        else:
            logger.info(
                f"Successfully reset repository {repo_name_from_patch} for CVE {cve_id}."
            )
    else:
        logger.warning(
            f"Repository path {repo_path.absolute()} invalid or CVE data missing or not a git repo. Skipping repository reset."  # Log absolute path
        )

    try:
        patch_set = PatchSet(StringIO(patch_content_str))
    except Exception as e:
        logger.error(
            f"Error parsing patch file {patch_file_path.name} with unidiff: {e}"
        )
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "repo_name_from_patch": repo_name_from_patch,
            "file_path_in_repo": None,
        }

    for patched_file in patch_set:
        try:
            file_path_in_repo = patched_file.target_file
            for hunk in patched_file:
                current_hunk_commit_hash = None  # Initialize commit_hash per hunk
                vulnerable_code_block = []
                context_lines = []

                vulnerable_lines_in_hunk = [
                    line_content for line_content in hunk.source_lines if line_content.startswith('-')
                ]

                for line_content in vulnerable_lines_in_hunk:
                    vulnerable_code_block.append(line_content[1:])  # Remove '-' prefix
                    current_line = (
                        hunk.source_start + hunk.source_lines.index(line_content)
                    )  # Calculate line number

                    # Extract context lines from hunk
                    context_start_index = max(
                        1, hunk.source_lines.index(line_content) - CONTEXT_LINES_BEFORE
                    ) if vulnerable_lines_in_hunk else 1 # avoid error if vulnerable_lines_in_hunk is empty
                    context_end_index = min(
                        len(hunk.source_lines),
                        (hunk.source_lines.index(line_content) + CONTEXT_LINES_AFTER) if vulnerable_lines_in_hunk else len(hunk.source_lines), # avoid error if vulnerable_lines_in_hunk is empty
                    ) if vulnerable_lines_in_hunk else len(hunk.source_lines) # avoid error if vulnerable_lines_in_hunk is empty
                    for context_line_index in range(
                        context_start_index - 1, context_end_index - 1
                    ):  # Adjust index to be 0-based
                        ctx_line = hunk.source_lines[context_line_index]
                        if not ctx_line.startswith(
                            (" ", "+", "-") # include '-' and '+' to be safe, although context lines should start with " "
                        ):  # Ensure it's a context line
                            context_lines.append(ctx_line[1:])  # Remove space prefix

                    if repo_path and file_path_in_repo:
                        # Execute git blame for the *first* vulnerable line in the hunk to get the introducing commit, only if not already done for this hunk
                        if (
                            vulnerable_lines_in_hunk
                            and line_content == vulnerable_lines_in_hunk[0]
                            and current_hunk_commit_hash
                            is None  # Check if commit_hash is already obtained for this hunk
                        ):
                            current_hunk_commit_hash = execute_git_blame(
                                repo_path, file_path_in_repo, current_line
                            )

                        vuln_info = {
                            "snippet": "\n".join(context_lines + vulnerable_code_block),
                            "introducing_commit": current_hunk_commit_hash,  # Use commit_hash obtained for the hunk
                            "cwe_id": cwe_id,
                            "cve_description": (
                                cve_data.get("vulnerability_details", {}).get(
                                    "description"
                                )
                                if cve_data
                                else None
                            ),
                            "line_number": current_line,
                        }
                        vulnerable_snippets.append(vuln_info)

        except AttributeError as e:
            logger.error(
                f"AttributeError processing diff in {patch_file_path.name}: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Error processing diff in {patch_file_path.name}: {str(e)}")
            continue

    if not vulnerable_snippets:
        logger.info(f"No vulnerable snippets found in {patch_file_path.name}")

    return {
        "cve_id": cve_id,
        "vulnerable_snippets": vulnerable_snippets,
        "repo_name_from_patch": repo_name_from_patch,
        "file_path_in_repo": file_path_in_repo,
    }


def execute_git_blame(
    repo_path: Path, file_path_in_repo: str, line_number: int
) -> Optional[str]:
    """
    Executes git blame command and returns the commit hash.
    """
    try:
        command = [
            "/usr/bin/git",
            "blame",
            "--porcelain",  # Use porcelain format for easier parsing
            "-L",
            f"{line_number},{line_number}",
            file_path_in_repo,
        ]
        logger.debug(
            f"Executing git blame command: {' '.join(command)} in {repo_path}"
        )  # ADDED LOGGING HERE
        process = subprocess.Popen(
            command, cwd=repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate(timeout=15)  # Timeout to prevent hanging

        if process.returncode != 0:  # Check return code
            error_message = stderr.decode("utf-8", errors="replace")
            logger.error(
                f"Git blame failed with return code {process.returncode}: {error_message} for file {file_path_in_repo}, line {line_number}"  # More context in error log
            )
            return None

        if (
            stderr
        ):  # This part might be redundant now with return code check, but keep it for now.
            error_message = stderr.decode("utf-8", errors="replace")
            if (
                "fatal: file " in error_message
                and "has only" in error_message
                and "lines" in error_message
            ):
                logger.warning(
                    f"Git blame line number error for {file_path_in_repo} line {line_number}: {error_message.strip()}"
                )  # Log as warning if line number issue
            else:  # Log as error for other git blame issues
                logger.error(
                    f"Git blame error for {file_path_in_repo} line {line_number}: {stderr.decode('utf-8', errors='replace')}"
                )
            return None

        blame_output = stdout.decode()
        # Parse porcelain output to get commit hash (first line is commit hash)
        commit_hash_line = blame_output.splitlines()[0]
        commit_hash = commit_hash_line.split(" ")[0]  # Extract commit hash
        return commit_hash

    except subprocess.TimeoutExpired:
        logger.error(f"Git blame timed out for {file_path_in_repo} line {line_number}")
        return None
    except FileNotFoundError:
        logger.error(
            "FileNotFoundError: Git command not found. Is Git installed and in PATH?"
        )  # Changed error message to include FileNotFoundError
        return None
    except UnicodeDecodeError as e:
        logger.error(f"UnicodeDecodeError decoding git blame output: {e}")
        return None
    except IndexError as e:
        logger.error(f"IndexError parsing git blame output: {e}")
        return None
    except Exception as e:
        logger.error(
            f"Error executing git blame for {file_path_in_repo} line {line_number}: {e}"
        )
        return None


def main():
    logger.info(f"Current PATH environment variable: {os.environ['PATH']}")  # Log PATH
    load_state()  # Load state at start

    patch_files = list(PATCHES_DIR.glob("*.patch"))
    if not patch_files:
        logger.warning(
            f"No patch files found in {PATCHES_DIR.absolute()}."  # Log absolute path
        )
        return

    patch_files_to_process = [
        f for f in patch_files if f.name not in PROCESSED_PATCHES
    ]  # Filter out already processed patches

    if not patch_files_to_process:
        logger.info("No new patch files to process.")
        return

    logger.info(
        f"Analyzing {len(patch_files_to_process)} new patch files from {PATCHES_DIR.absolute()}..."  # Log absolute path
    )

    output_data = []  # List to store structured output

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                analyze_patch_file,
                patch_file,
            ): patch_file  # Removed token_manager from function call
            for patch_file in patch_files_to_process
        }
        for future in tqdm(
            as_completed(futures), total=len(futures), desc="Analyzing Patches"
        ):
            patch_file = futures[future]
            try:
                analysis_result = future.result()
                if analysis_result["vulnerable_snippets"]:
                    logger.info(f"\n--- Analysis for {analysis_result['cve_id']} ---")
                    logger.info("\nVulnerable Code Snippets:")
                    repo_name_from_patch = analysis_result.get(
                        "repo_name_from_patch"
                    )  # Get repo name from result
                    file_path_in_repo = analysis_result.get(
                        "file_path_in_repo"
                    )  # Get file path from result
                    for vuln_info in analysis_result["vulnerable_snippets"]:
                        logger.info(
                            f"Line: {vuln_info['line_number']}, CWE: {vuln_info['cwe_id']}"
                        )  # Print line number and CWE
                        logger.info(vuln_info["snippet"])  # Print code snippet
                        if vuln_info["introducing_commit"]:
                            logger.info(
                                f"  Introducing commit (git blame): {vuln_info['introducing_commit']}"
                            )
                        else:
                            logger.info(
                                "  Introducing commit: Not automatically determined."
                            )

                        logger.info("---")

                        output_data.append(
                            {  # Add to output data for each snippet
                                "cve_id": analysis_result["cve_id"],  # Include CVE ID
                                "file_path": (
                                    file_path_in_repo if file_path_in_repo else None
                                ),  # Use file_path_in_repo directly
                                "line_number": vuln_info["line_number"],
                                "cwe_id": vuln_info["cwe_id"],
                                "cve_description": vuln_info["cve_description"],
                                "code_snippet": vuln_info["snippet"],
                                "introducing_commit": vuln_info[
                                    "introducing_commit"
                                ],  # Add introducing commit to output
                            }
                        )

                else:
                    logger.info(f"No vulnerable snippets found in {patch_file.name}")
            except KeyError as e:
                logger.error(f"KeyError accessing analysis result: {e}")
            except Exception as e:
                logger.error(f"Error analyzing {patch_file.name}: {e}")
            finally:
                PROCESSED_PATCHES.add(
                    patch_file.name
                )  # Mark as processed after each file
                save_state()  # Save state after each file

    with open(OUTPUT_FILE, "w") as outfile:  # Write output data to JSON file
        json.dump(output_data, outfile, indent=2)
    logger.info(
        f"Vulnerable code snippets saved to {OUTPUT_FILE.absolute()}"
    )  # Log absolute path

    logger.info("\nAnalysis completed.")
    logger.info(f"Script finished at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
