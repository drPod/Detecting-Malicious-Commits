# This script uses the patches/ directory to find vulnerability introducing commits for each CVE.
import os
import re
from pathlib import Path
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, TYPE_CHECKING
from io import StringIO
from diff_parser import Diff  # Changed import from DiffParser to Diff
from unidiff import PatchSet  # Import PatchSet from unidiff
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from github_data_collector import (
    TokenManager,
    load_github_tokens,
)  # Import TokenManager

if TYPE_CHECKING:
    from github_data_collector import TokenManager
import subprocess  # For running git blame

# --- Configuration ---
# Directories and files
PATCHES_DIR = Path("patches")  # Directory containing patch files
REPOS_DIR = Path("repos")
NVD_DATA_DIR = Path("nvd_data")  # Add NVD data directory
LOG_FILE = Path("introducing_commit_finder.log")
OUTPUT_FILE = Path("vulnerable_code_snippets.json")  # Output JSON file for results

# Setup logging
LOG_LEVEL = logging.DEBUG  # Set default log level
CONTEXT_LINES_BEFORE = 2  # Configurable context lines before vulnerable line
CONTEXT_LINES_AFTER = 3  # Configurable context lines after vulnerable line
MAX_WORKERS = 10  # Number of threads for parallel processing
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
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning(
                f"No valid state file found at {STATE_FILE}, starting from scratch."
            )


def save_state():
    """Save processed patches state to JSON file."""
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(PROCESSED_PATCHES), f)
        logger.info(f"Saved state for {len(PROCESSED_PATCHES)} patches to {STATE_FILE}")
    except Exception as e:
        logger.error(f"Error saving state to {STATE_FILE}: {e}")


logger.info(f"Output file: {OUTPUT_FILE.absolute()}")


def load_cve_data(cve_id: str) -> Optional[Dict[str, Any]]:
    """Load CVE data from JSON file."""
    cve_file = NVD_DATA_DIR / f"{cve_id}.json"
    if not cve_file.exists():
        logger.warning(f"CVE data file not found: {cve_file}")
        return None
    try:
        with open(cve_file, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from {cve_file}")
        return None


def analyze_patch_file(
    patch_file_path: Path, token_manager: Optional["TokenManager"] = None
):
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

    # Read patch file content
    try:
        with open(patch_file_path, "r") as f:
            patch_content_str = f.read()
    except FileNotFoundError:
        logger.error(f"Patch file not found: {patch_file_path}")
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "repo_name_from_patch": None,
            "file_path_in_repo": None,
        }

    # Extract repo name from patch file name
    try:
        repo_name_from_patch = patch_file_path.name.replace(f"{cve_id}_", "").replace(
            ".patch", ""
        )
        if not repo_name_from_patch:
            raise ValueError("Empty repo name")
        repo_path = REPOS_DIR / repo_name_from_patch
    except Exception as e:
        logger.error(f"Failed to extract repo name: {e}")
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "repo_name_from_patch": None,
            "file_path_in_repo": None,
        }

    # Find all diff headers in the patch content
    diff_headers = re.finditer(r"(?m)^diff --git a/(.+?) b/(.+?)$", patch_content_str)
    if not diff_headers:
        logger.debug(f"No git diff headers found in {patch_file_path.name}")
        # Try unified diff format
        diff_headers = re.finditer(
            r"(?m)^--- a/(.+?)\n\+\+\+ b/(.+?)$", patch_content_str
        )

    files_processed = False
    for diff_header in diff_headers:
        files_processed = True
        try:
            # Extract file path from diff header
            if len(diff_header.groups()) >= 2:
                file_path_in_repo = diff_header.group(2)  # Use the 'b' path
            else:
                file_path_in_repo = diff_header.group(1)  # Fallback to first group

            # Parse the diff using unidiff
            patch_set = PatchSet(StringIO(patch_content_str))

            for patched_file in patch_set:
                for hunk in patched_file:
                    vulnerable_code_block = []
                    context_lines = []

                    # Track line numbers
                    current_line = hunk.source_start

                    for line in hunk:
                        if line.is_removed:
                            # Store vulnerable line
                            vulnerable_code_block.append(
                                line.value[1:]
                            )  # Remove the '-' prefix

                            # Collect context (before and after)
                            context_start = max(0, current_line - CONTEXT_LINES_BEFORE)
                            context_end = current_line + CONTEXT_LINES_AFTER

                            # Add context lines
                            for ctx_line in hunk.source[context_start:context_end]:
                                if not ctx_line.startswith(("-", "+")):
                                    context_lines.append(
                                        ctx_line[1:]
                                    )  # Remove space prefix

                            if repo_path and file_path_in_repo:
                                commit_hash = execute_git_blame(
                                    repo_path, file_path_in_repo, current_line
                                )

                                vuln_info = {
                                    "snippet": "\n".join(
                                        context_lines + vulnerable_code_block
                                    ),
                                    "cwe_id": cwe_id,
                                    "cve_description": (
                                        cve_data.get("vulnerability_details", {}).get(
                                            "description"
                                        )
                                        if cve_data
                                        else None
                                    ),
                                    "line_number": current_line,
                                    "introducing_commit": commit_hash,
                                }
                                vulnerable_snippets.append(vuln_info)

                        if not line.is_added:  # Count original lines
                            current_line += 1

        except Exception as e:
            logger.error(f"Error processing diff in {patch_file_path.name}: {str(e)}")
            continue

    if not files_processed:
        logger.warning(f"No valid diff content found in {patch_file_path.name}")

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
            "git",
            "blame",
            "--porcelain",  # Use porcelain format for easier parsing
            "-L",
            f"{line_number},{line_number}",
            file_path_in_repo,
        ]
        logger.debug(f"Executing git blame command: {' '.join(command)} in {repo_path}") # ADDED LOGGING HERE
        process = subprocess.Popen(
            command, cwd=repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = process.communicate(timeout=15)  # Timeout to prevent hanging

        if stderr:
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
        logger.error("Git command not found. Is Git installed and in PATH?")
        return None
    except Exception as e:
        logger.error(
            f"Error executing git blame for {file_path_in_repo} line {line_number}: {e}"
        )
        return None


def main():
    load_state()  # Load state at start

    tokens = (
        load_github_tokens()
    )  # Load tokens for TokenManager - even if not directly used now, for future use.
    token_manager = TokenManager(tokens)  # Initialize TokenManager

    patch_files = list(PATCHES_DIR.glob("*.patch"))
    if not patch_files:
        logger.warning(
            f"No patch files found in {PATCHES_DIR}. Please run patch_downloader.py first."
        )
        save_state()  # Save state before exit, even if no patches
        return

    patch_files_to_process = [
        f for f in patch_files if f.name not in PROCESSED_PATCHES
    ]  # Filter out already processed patches

    if not patch_files_to_process:
        logger.info("No new patch files to process.")
        save_state()  # Save state before exit, if no new patches
        return

    logger.info(
        f"Analyzing {len(patch_files_to_process)} new patch files from {PATCHES_DIR}..."
    )

    output_data = []  # List to store structured output

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                analyze_patch_file,
                patch_file,
                token_manager,  # Pass token_manager to analyze_patch_file - FINAL VERSION, TOKEN_MANAGER NOT USED
            ): patch_file  # token_manager passed to analyze_patch_file
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
            except Exception as e:
                logger.error(f"Error analyzing {patch_file.name}: {e}")
            finally:
                PROCESSED_PATCHES.add(
                    patch_file.name
                )  # Mark as processed after each file
                save_state()  # Save state after each file

    with open(OUTPUT_FILE, "w") as outfile:  # Write output data to JSON file
        json.dump(output_data, outfile, indent=2)
    logger.info(f"Vulnerable code snippets saved to {OUTPUT_FILE}")

    logger.info("\nAnalysis completed.")
    logger.info(f"Script finished at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
    save_state()  # Final state save on normal exit
