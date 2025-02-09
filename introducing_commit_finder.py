# This script uses the patches/ directory to find vulnerability introducing commits for each CVE.
import os
import re
from pathlib import Path
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, TYPE_CHECKING
from diff_parser import Diff  # Changed import from DiffParser to Diff
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
    """# token_manager: Optional['TokenManager'] = None - FINAL VERSION - TOKEN_MANAGER PASSED BUT NOT USED
    Analyzes a patch file to identify vulnerable code snippets and generate git blame commands.
    """
    vulnerable_snippets: List[Dict[str, Any]] = []
    git_blame_commands: List[str] = (
        []
    )  # No longer used for commands, but kept for potential future use or debugging - REMOVE GIT_BLAME_COMMANDS COMPLETELY
    repo_path = None
    repo_name_from_patch = None  # Store repo name
    file_path_in_repo = None
    patch_content_str = ""
    cve_id = patch_file_path.name.split("_")[0]
    cve_data = load_cve_data(cve_id)  # Load CVE data
    cwe_id = (
        cve_data.get("vulnerability_details", {}).get("cwe_id") if cve_data else None
    )  # Extract CWE ID

    logger.info(f"Analyzing patch file: {patch_file_path.name}")
    try:
        with open(patch_file_path, "r") as f:
            patch_content_str = (
                f.read()
            )  # Read entire patch content as string for diff_parser
            patch_content_lines = (
                f.readlines()
            )  # Keep lines for manual parsing of filepath (if needed)
    except FileNotFoundError:
        logger.error(f"Patch file not found: {patch_file_path}")
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "git_blame_commands": [],
            "repo_name_from_patch": None,  # Return None if error
            "file_path_in_repo": None,  # Return None if error
        }

    diff_header_line = next(
        (
            line
            for line in patch_content_lines
            if "--- a/" in line.strip().lower()  # Relaxed and case-insensitive check
        ),
        None,  # Use lines to find filepath
    )

    if diff_header_line:  # Extract filepath from diff header
        file_path_in_patch = diff_header_line.split("--- a/")[1].strip()
        file_path_in_repo = file_path_in_patch  # Use path from patch header
        repo_name_from_patch = patch_file_path.name.replace(
            cve_id + "_", ""
        ).replace(  # Extract repo name
            ".patch", ""
        )
        if not repo_name_from_patch:  # Handle cases where repo name extraction fails
            logger.error(
                f"Could not extract repo name from patch file name: {patch_file_path.name}"
            )
            return {
                "cve_id": cve_id,
                "vulnerable_snippets": [],
                "git_blame_commands": [],
                "repo_name_from_patch": None,  # Return None if extraction fails
                "file_path_in_repo": None,  # Return None if extraction fails
            }
        repo_path = REPOS_DIR / repo_name_from_patch  # Correctly use REPOS_DIR
    else:
        logger.debug(  # Changed to debug level
            f"No diff header found in {patch_file_path.name}. Skipping file path extraction."
        )
        logger.debug(
            f"First 10 lines of patch file {patch_file_path.name}:"
        )  # Debug log for first lines
        for i, line in enumerate(patch_content_lines[:10]):  # Log first 10 lines
            logger.debug(f"Line {i+1} - content: '{line.strip()}' - '--- a/' in line: {'--- a/' in line.strip().lower()}") # DEBUGGING: Log line content and check
            logger.debug(
                f"Line {i+1}: {line.strip()}"
            )  # Log with line number and stripped content
        logger.warning(  # Keep warning log for important cases
            f"No '--- a/' diff header found in {patch_file_path.name}. File path extraction may be incomplete."
        )
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "git_blame_commands": [],
            "repo_name_from_patch": None,  # Return None if no diff header
            "file_path_in_repo": None,  # Return None if no diff header
        }

    try:
        diff = Diff(
            patch_content_str
        )  # Parse the patch content using diff_parser - Use Diff instead of DiffParser

        # if not diff.files:  # diff object from Diff does not have 'files' attribute. Remove this check.
        #     logger.warning(
        #         f"No files found in diff content for {patch_file_path.name}. Diff Parser might have failed."
        #     )
        #     return {
        #         "cve_id": cve_id,
        #         "vulnerable_snippets": [],
        #         "git_blame_commands": [],
        #         "repo_name_from_patch": repo_name_from_patch,  # Return extracted repo name
        #         "file_path_in_repo": file_path_in_repo,  # Return extracted file path
        #     }

        for (
            block
        ) in (
            diff
        ):  # Iterate over each block in the diff - Use 'block' as per documentation
            diff_file_path = block.new_filepath  # Use block.new_filepath as file path
            if not diff_file_path:  # Robust check for file path
                logger.warning(
                    f"No file path found in diff for {patch_file_path.name} in block"
                )
                continue
            file_path_in_repo = diff_file_path  # Use block.new_filepath as file path
            # for hunk in file_diff.hunks:  # No hunks in Diff output, iterate changes directly
            for change in block.changes:  # Iterate over changes in block
                vulnerable_code_block = (
                    []
                )  # Store vulnerable code lines for current change
                context_lines_for_snippet = (
                    []
                )  # Store context lines for the current vulnerable snippet

                # Iterate through lines in hunk.lines which are Line instances, not just strings
                # for line_obj in hunk.lines: # No line_obj in change, content is directly string
                change_content_lines = (
                    change.content.splitlines()
                )  # Split change content to lines for processing
                original_line_start = change.original_line_start
                modified_line_start = change.modified_line_start

                for i, line_content in enumerate(
                    change_content_lines
                ):  # Iterate over lines in change.content
                    if line_content.startswith(
                        "-"
                    ):  # Identify removed lines (potential vulnerability)
                        vulnerable_code_block.append(
                            line_content[1:]  # Remove '-' prefix
                        )  # Add removed line content
                        context_lines = []  # Context for each vulnerable line

                        # Collect context lines (before and after the vulnerable line within the change)
                        line_index_in_change = i
                        context_start_index = max(
                            0, line_index_in_change - CONTEXT_LINES_BEFORE
                        )
                        context_end_index = min(
                            len(change_content_lines),
                            line_index_in_change + CONTEXT_LINES_AFTER + 1,
                        )

                        for context_idx in range(
                            context_start_index, context_end_index
                        ):
                            context_line_content = change_content_lines[context_idx]
                            if context_line_content.startswith(
                                " "
                            ):  # Context lines start with space
                                context_lines.append(
                                    context_line_content[1:]
                                )  # Remove ' ' prefix

                        context_lines_for_snippet.extend(
                            context_lines
                        )  # Add context lines to the current snippet's context

                        vuln_info = {
                            "snippet": "\n".join(
                                context_lines_for_snippet + vulnerable_code_block
                            ),  # Vulnerable code + context
                            # Include CWE ID
                            "cwe_id": cwe_id,  # Include CWE ID
                            "cve_description": (
                                cve_data.get("vulnerability_details", {}).get(
                                    "description"
                                )
                                if cve_data
                                else None
                            ),
                            # Access line number from change, using original_line_start and line index. Approximation!
                            "line_number": (
                                original_line_start + i
                                if original_line_start
                                else modified_line_start + i
                            ),  # Approximation of line number
                            "introducing_commit": None,  # Initialize introducing_commit to None
                        }

                        if (
                            repo_path and file_path_in_repo
                        ):  # Ensure repo_path and file_path_in_repo are valid
                            commit_hash = execute_git_blame(
                                repo_path,
                                file_path_in_repo,
                                vuln_info["line_number"],
                                # token_manager # TokenManager passed to analyze_patch_file, but not used in execute_git_blame - FINAL VERSION, TOKEN_MANAGER NOT USED
                            )
                            vuln_info["introducing_commit"] = (
                                commit_hash  # Store the commit hash
                            )

                        vulnerable_snippets.append(vuln_info)

    except Exception as e:
        logger.error(f"Error parsing patch hunk in {patch_file_path.name}: {e}")
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "git_blame_commands": [],
            "repo_name_from_patch": repo_name_from_patch,  # Return extracted repo name even if error
            "file_path_in_repo": file_path_in_repo,  # Return extracted file path even if error
        }

    return {
        "cve_id": cve_id,
        "vulnerable_snippets": vulnerable_snippets,
        "git_blame_commands": git_blame_commands,  # Still return, might be useful for debugging or future features
        "repo_name_from_patch": repo_name_from_patch,  # Return extracted repo name
        "file_path_in_repo": file_path_in_repo,  # Return extracted file path
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
