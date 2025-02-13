# This script uses the patches/ directory to find vulnerability introducing commits for each CVE.
import os
import re
from pathlib import Path
import logging
import json
from datetime import datetime
import dotenv
from typing import List, Dict, Any, Optional
from io import StringIO
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import google.generativeai as genai  # For Gemini model integration
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
    os.environ.get("OUTPUT_FILE_DIR", "vulnerable_code_snippets")
)  # Output directory for results

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
                )  # Debug log
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
        if (
            not commit_hash and default_branch == "main"
        ):  # If no commit found on 'main', try 'master'
            logger.debug(
                f"No commit found on 'main' branch, trying 'master' as fallback."
            )
            command_rev_list_master = [
                "/usr/bin/git",
                "rev-list",
                f"--before='{date_str_for_git}'",
                "--max-count=1",
                "master",  # Trying 'master' branch
            ]
            process_rev_list_master = subprocess.Popen(
                command_rev_list_master,
                cwd=repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_rev_list_master, stderr_rev_list_master = (
                process_rev_list_master.communicate(timeout=30)
            )
            if process_rev_list_master.returncode == 0:
                commit_hash = stdout_rev_list_master.decode("utf-8").strip()
                if commit_hash:
                    default_branch = (
                        "master"  # Update default_branch to 'master' if commit found
                    )
                    logger.info(f"Found commit on 'master' branch as fallback.")
                else:
                    logger.warning(f"No commit found on 'master' branch either.")
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


def analyze_with_gemini(
    repo_path: Path, repo_name_from_patch: str, cve_id: str, patch_file_path: Path, model
):  # Removed logger parameter as it's globally available
    """
    Analyzes a patch using the Gemini model to identify vulnerable code snippets.
    """

    vulnerable_snippets = []  # Initialize outside the try block for consistent return

    try:
        if not repo_path or not repo_path.exists() or not repo_path.is_dir():
            raise ValueError(f"Invalid repository path: {repo_path}")
        if not (repo_path / ".git").exists():
            raise ValueError(f"Not a git repository: {repo_path}")

        repo_name_for_prompt = "".join(
            c if c.isalnum() or c in [".", "_", "-"] else "_"
            for c in repo_name_from_patch or "unknown_repository"
        )
        cve_id_for_prompt = "".join(
            c if c.isalnum() or c in [".", "_", "-"] else "_" for c in cve_id
        )

        prompt_text = f"""
        Analyze the patch for CVE ID {cve_id_for_prompt} applied to the repository named '{repo_name_for_prompt}'.
        Identify the lines in the patched files that are vulnerable and need to be analyzed with git blame to find the introducing commit.
        Return a JSON formatted list of dictionaries enclosed in ```json and ``` markers.
        Each dictionary should contain 'file_path' and 'line_numbers' keys.
        'file_path' is the path to the file in the repository.
        'line_numbers' is a list of integers representing the vulnerable line numbers in that file.
        Example:
        ```json
        [{"file_path": "path/to/file.c", "line_numbers": [123, 125]}, {"file_path": "another/file.java", "line_numbers": [50]}]
        ```
        """

        logger.debug(f"Prompt sent to Gemini API for {cve_id}: {prompt_text}")

        try:  # Inner try for Gemini API interaction
            response = model.generate_content(prompt_text)
            gemini_output = response.text
            logger.debug(
                f"Gemini Model Output for {cve_id}:\n{gemini_output}"
            )  # Log with newline for readability

        except Exception as e:  # Catch Gemini specific errors
            logger.error(f"Error communicating with Gemini API for {cve_id}: {e}")
            return {
                "cve_id": cve_id,
                "vulnerable_snippets": [],
                "repo_name_from_patch": repo_name_from_patch,
                "file_path_in_repo": None,
            }

        try:  # JSON parsing
            start_marker = "```json"
            end_marker = "```"
            start_index = gemini_output.find(start_marker)
            end_index = gemini_output.find(end_marker, start_index + len(start_marker))

            if start_index != -1 and end_index != -1:
                json_string = gemini_output[
                    start_index + len(start_marker) : end_index
                ].strip()
                vulnerable_snippets_raw = json.loads(json_string)

                if not isinstance(vulnerable_snippets_raw, list):
                    raise TypeError(
                        f"Gemini output not a list: {type(vulnerable_snippets_raw)}"
                    )

                for item in vulnerable_snippets_raw: # type: ignore
                    if (
                        not isinstance(item, dict)
                        or "file_path" not in item
                        or "line_numbers" not in item
                    ):
                        raise ValueError(
                            f"Invalid item format in Gemini output: {item}"
                        )
                    vulnerable_snippets.append(item)
            else:
                raise ValueError("JSON markers not found in Gemini output.")

        except (json.JSONDecodeError, TypeError, ValueError) as e:
            logger.error(
                f"Error processing Gemini output for {cve_id}: {e}. Raw output:\n{gemini_output}"
            )  # Include raw output in error log
            # vulnerable_snippets remains empty

    except ValueError as e:  # For repo path issues
        logger.warning(str(e))  # Log the specific error message
        # vulnerable_snippets remains empty

    except Exception as e:  # Catch any other unexpected exceptions
        logger.error(f"Unexpected error during Gemini analysis for {cve_id}: {e}")
        # vulnerable_snippets remains empty

    # Git blame analysis to find introducing commits
    if vulnerable_snippets and repo_path and (repo_path / ".git").exists():
        vulnerable_snippets_with_commits: List[Dict[str, Any]] = []
        for snippet in vulnerable_snippets:
            file_path_in_repo = repo_path / snippet["file_path"]
            if not file_path_in_repo.exists() or not file_path_in_repo.is_file():
                logger.warning(
                    f"File '{snippet['file_path']}' from Gemini output not found in repository at {file_path_in_repo.absolute()}. Skipping git blame for this file."
                )
                vulnerable_snippets_with_commits.append(
                    {**snippet, "introducing_commits": {}}
                )  # Keep snippet info, but no blame
                continue

            introducing_commits_for_file: Dict[int, str] = {} # line_number: commit_hash
            for line_number in snippet["line_numbers"]:
                try:
                    command_blame = [
                        "/usr/bin/git",
                        "blame",
                        "-L",
                        f"{line_number},{line_number}",
                        "--porcelain", # for easier parsing
                        str(snippet["file_path"]),
                    ]
                    logger.debug(
                        f"Executing git blame command: {' '.join(command_blame)} in {repo_path}"
                    )
                    process_blame = subprocess.Popen(
                        command_blame,
                        cwd=repo_path,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    stdout_blame, stderr_blame = process_blame.communicate(timeout=30)

                    if process_blame.returncode != 0:
                        error_message = stderr_blame.decode("utf-8", errors="replace")
                        logger.error(
                            f"Git blame error for {cve_id}, file {snippet['file_path']}, line {line_number} with return code {process_blame.returncode}: {error_message}"
                        )
                        introducing_commits_for_file[line_number] = "blame_error" # Indicate blame error
                    else:
                        blame_output = stdout_blame.decode("utf-8", errors="replace")
                        # Parse git blame porcelain output to get commit hash
                        commit_hash_match = re.search(r"^([0-9a-f]{40}) ", blame_output, re.MULTILINE)
                        if commit_hash_match:
                            commit_hash = commit_hash_match.group(1)
                            introducing_commits_for_file[line_number] = commit_hash
                            logger.debug(
                                f"Git blame found commit {commit_hash} for {cve_id}, file {snippet['file_path']}, line {line_number}"
                            )
                        else:
                            logger.warning(
                                f"Could not parse commit hash from git blame output for {cve_id}, file {snippet['file_path']}, line {line_number}. Output: {blame_output}"
                            )
                            introducing_commits_for_file[line_number] = "parse_error" # Indicate parse error

                except subprocess.TimeoutExpired:
                    logger.error(f"Git blame timed out for {cve_id}, file {snippet['file_path']}, line {line_number}")
                    introducing_commits_for_file[line_number] = "timeout_error" # Indicate timeout
                except FileNotFoundError:
                    logger.error("Git blame command not found. Is Git installed and in PATH?")
                    introducing_commits_for_file[line_number] = "git_not_found" # Indicate git not found
                except Exception as e:
                    logger.error(f"Unexpected error during git blame for {cve_id}, file {snippet['file_path']}, line {line_number}: {e}")
                    introducing_commits_for_file[line_number] = "exception_error" # Indicate exception

            vulnerable_snippets_with_commits.append({**snippet, "introducing_commits": introducing_commits_for_file}) # Add blame results
        vulnerable_snippets = vulnerable_snippets_with_commits # Replace original snippets with enriched ones

    if not vulnerable_snippets:
        logger.info(
            f"No vulnerable snippets found in {patch_file_path.name if patch_file_path else 'unknown patch file'}"
        )
        if gemini_output: # Only log if there was gemini output to begin with
            logger.debug(f"Gemini output for {cve_id}: {gemini_output}") # Log Gemini output if no vulnerable snippets found

    return {
        "cve_id": cve_id,
        "vulnerable_snippets": vulnerable_snippets,
        "repo_name_from_patch": repo_name_from_patch,
        "file_path_in_repo": None,
    }


def analyze_patch_file(patch_file_path: Path, model):  # Added model parameter
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

    vulnerable_snippets: List[Dict[str, Any]] = (
        []
    )  # Initialize vulnerable_snippets here

    return analyze_with_gemini(
        repo_path, repo_name_from_patch, cve_id, patch_file_path, model
    )  # Pass model parameter


def main():
    logger.info(f"Current PATH environment variable: {os.environ['PATH']}")  # Log PATH

    dotenv.load_dotenv()  # Load environment variables from .env file

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

    # Initialize Gemini model in main function
    try:
        genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
        gemini_model = genai.GenerativeModel("gemini-2.0-flash")
        logger.info("Gemini model initialized successfully in main.")
    except Exception as e:
        logger.error(f"Error initializing Gemini model in main: {e}")
        gemini_model = None  # Handle case where model initialization fails

    OUTPUT_FILE.mkdir(
        parents=True, exist_ok=True
    )  # Create output directory if it doesn't exist

    executor = ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    )  # Create executor outside try block
    try:
        with executor:  # Use context manager for proper shutdown
            futures = {
                executor.submit(
                    analyze_patch_file,
                    patch_file,
                    gemini_model,  # Pass initialized Gemini model
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
                        logger.info(
                            f"\n--- Analysis for {analysis_result['cve_id']} ---"
                        )
                        output_file_path_cve = (
                            OUTPUT_FILE / f"{analysis_result['cve_id']}.json"
                        )
                        try:
                            with open(output_file_path_cve, "w") as outfile:
                                json.dump(
                                    analysis_result["vulnerable_snippets"],
                                    outfile,
                                    indent=2,
                                )
                            logger.info(
                                f"Vulnerable lines saved to {output_file_path_cve.absolute()}"
                            )
                        except Exception as e:
                            logger.error(
                                f"Error saving vulnerable lines to {output_file_path_cve.absolute()}: {e}"
                            )

                        # Log the structured data
                        for vuln_file_info in analysis_result["vulnerable_snippets"]:
                            logger.info(f"  File: {vuln_file_info['file_path']}")
                            logger.info(
                                f"  Vulnerable Lines: {vuln_file_info['line_numbers']}"
                            )
                            if "introducing_commits" in vuln_file_info:
                                for line_num, commit_hash in vuln_file_info["introducing_commits"].items():
                                    logger.info(
                                        f"    Line {line_num} introducing commit: {commit_hash}"
                                    )

                            logger.info(
                                "---"
                            )  # Separator for different file info blocks

                    else:
                        logger.info(
                            f"No vulnerable snippets found in {patch_file.name}"
                        )
                except Exception as e:
                    logger.error(f"Error analyzing {patch_file.name}: {e}")
                finally:
                    PROCESSED_PATCHES.add(
                        patch_file.name
                    )  # Mark as processed after each file
    except KeyboardInterrupt:
        logger.info("Script interrupted by user. Shutting down executor...")
        executor.shutdown(
            wait=False
        )  # Cancel pending tasks, but don't wait for current ones to finish immediately
        logger.info("Executor shutdown initiated.")
    finally:  # Ensure state is saved even on normal completion or interruption
        save_state()  # Save state at the end

    logger.info("\nAnalysis completed.")
    logger.info(f"Script finished at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
