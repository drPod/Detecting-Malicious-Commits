# This script uses the patches/ directory to find vulnerability introducing commits for each CVE.
import os
import re
import time
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
import google.api_core.exceptions  # For Google API exceptions
import google.generativeai.types.generation_types  # For Gemini specific types
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
LOG_LEVEL = logging.INFO  # Set default log level
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


def parse_gemini_json_output(gemini_output: str, cve_id: str, attempt_number: int) -> List[Dict[str, Any]]:
    """Parses JSON from Gemini output with improved robustness and error handling."""
    start_marker = "```json"
    end_marker = "```"
    start_index = gemini_output.find(start_marker)
    end_index = gemini_output.find(end_marker, start_index + len(start_marker))

    if start_index != -1 and end_index != -1:
        json_string = gemini_output[start_index + len(start_marker) : end_index].strip()
        if not json_string:  # Check if anything is actually between markers
            raise ValueError("No JSON content found between markers.")
        try:
            vulnerable_snippets_raw = json.loads(json_string)
            if not isinstance(vulnerable_snippets_raw, list):
                raise TypeError(
                    f"Gemini output is not a list, but {type(vulnerable_snippets_raw)}."
                )
            return vulnerable_snippets_raw
        except json.JSONDecodeError as e:
            error_snippet = (
                json_string[:100] + "..." if len(json_string) > 100 else json_string
            )  # Snippet for logging
            logger.error(
                f"JSONDecodeError on Gemini output for CVE {cve_id}, attempt {attempt_number}: {e}. Snippet: {error_snippet}"
            )
            raise  # Re-raise for follow-up handling
    else:
        raise ValueError("JSON markers '```json' and '```' not found in Gemini output.")


def analyze_with_gemini(
    repo_path: Path,
    repo_name_from_patch: str,
    cve_id: str,
    patch_file_path: Path,
    models,
):  # Removed logger parameter as it's globally available
    """
    Analyzes a patch using the Gemini model to identify vulnerable code snippets.
    """

    vulnerable_snippets = []  # Initialize outside the try block for consistent return
    logger.debug(f"Entering analyze_with_gemini for CVE: {cve_id}")

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

        logger.debug(f"Checkpoint before prompt construction for {cve_id}")

        prompt_part1 = "[DEBUG PROMPT START]\nAnalyze the patch for CVE ID "
        prompt_part2 = f"{cve_id_for_prompt} "
        prompt_part3 = "applied to the repository named "
        prompt_part4 = f"'{repo_name_for_prompt}'.\n"
        prompt_part5 = "Identify the lines in the patched files that are vulnerable and need to be analyzed with git blame to find the introducing commit.\n"
        prompt_part6 = "Return a JSON formatted list of dictionaries enclosed in ```json and ``` markers.\n"
        prompt_part7 = (
            "Each dictionary should contain 'file_path' and 'line_numbers' keys.\n"
        )
        prompt_part8 = "'file_path' is the path to the file in the repository.\n"
        prompt_part9 = "'line_numbers' is a list of integers representing the vulnerable line numbers in that file.\n"
        prompt_part10 = 'Example:\n```json\n[{"file_path": "path/to/file.c", "line_numbers": [123, 125]}, {"file_path": "another/file.java", "line_numbers": [50]}]\n```\n'
        prompt_part11 = "[DEBUG PROMPT END]"

        prompt_text = (
            prompt_part1
            + prompt_part2
            + prompt_part3
            + prompt_part4
            + prompt_part5
            + "Return a JSON formatted list of dictionaries enclosed in ```json and ``` markers. **Ensure the JSON is valid and contains no comments or any text outside the JSON block.**\n"
            + prompt_part7
            + prompt_part8
            + prompt_part9
            + prompt_part10
            + prompt_part11
        )

        logger.debug(
            f"Prompt part 1: {prompt_part1.strip()}"
        )  # Log each part separately
        logger.debug(f"Prompt part 2: {prompt_part2.strip()}")
        logger.debug(f"Prompt part 3: {prompt_part3.strip()}")
        logger.debug(f"Prompt part 4: {prompt_part4.strip()}")
        logger.debug(
            f"Prompt sent to Gemini API for {cve_id}: {prompt_text}"
        )  # Log full prompt

        gemini_output = None
        for model_name in models:
            retry_count = 0
            max_retries = 15
            base_delay = 1  # seconds
            max_delay = 300  # seconds (5 minutes max delay)

            while retry_count <= max_retries:
                current_model = genai.GenerativeModel(model_name)
                try:  # Inner try for Gemini API interaction
                    logger.info(
                        f"Using Gemini model '{model_name}' for CVE: {cve_id}, attempt {retry_count + 1}"
                    )
                    response = current_model.generate_content(prompt_text)
                    logger.debug(
                        f"Gemini API Response object for {cve_id} with model '{model_name}': {response}"
                    )  # Log response object
                    gemini_output = response.text
                    logger.debug(
                        f"Gemini Model Output (Initial) for {cve_id} with model '{model_name}':\n{gemini_output}"
                    )  # Log with newline for readability
                    break  # Successful API call, exit retry loop

                except Exception as e:  # Catch Gemini specific errors, specifically rate limit errors
                    if "exceeded quota" in str(e) or "RateLimitError" in str(e) or "429" in str(e):  # Adjust error checking as needed, include HTTP 429
                        retry_count += 1
                        if retry_count <= max_retries:
                            delay = min(base_delay * (2**retry_count), max_delay)  # Exponential backoff with max cap
                            logger.warning(
                                f"Rate limit encountered for model '{model_name}' on CVE: {cve_id}, retry {retry_count}/{max_retries}. Waiting {delay} seconds before retrying."
                            )
                            time.sleep(delay)
                        else:
                            logger.error(
                                f"Max retries reached for model '{model_name}' on CVE: {cve_id} due to rate limits. Switching to next model if available."
                            )
                            break  # Move to the next model
                    else:
                        error_type = type(e).__name__
                        error_message = str(e)
                        if "BlockedPromptError" in error_type:
                            log_level = logger.warning
                        else:
                            log_level = logger.error # Default to error for other unexpected issues
                        log_level(f"Error communicating with Gemini API for CVE {cve_id} using model '{model_name}' ({error_type}): {error_message}")
                        if isinstance(e, google.api_core.exceptions.ServiceUnavailable): # Explicitly check for ServiceUnavailable
                            logger.warning(f"ServiceUnavailable error (HTTP 503) encountered for model '{model_name}' on CVE: {cve_id}. Consider retrying or switching models.")
                        elif isinstance(e, google.api_core.exceptions.InternalServerError): # Explicitly check for InternalServerError
                            logger.error(f"InternalServerError (HTTP 500) from Gemini API for CVE {cve_id} using model '{model_name}'. This indicates a server-side issue.")
                        elif isinstance(e, google.generativeai.types.generation_types.BlockedPromptError):
                            logger.warning(f"Gemini API blocked the prompt for CVE {cve_id} using model '{model_name}'. Review prompt or model.")
                        return {"cve_id": cve_id, "vulnerable_snippets": [], "repo_name_from_patch": repo_name_from_patch, "file_path_in_repo": None} # Non-rate-limit error, no retry or model switch for now
            if gemini_output: # if gemini_output is not None, it means we got a valid response from one of the models
                break # exit model loop as well
        if not gemini_output: # if after trying all models, we still don't have output, then return error
            logger.error(f"Failed to get Gemini output for CVE: {cve_id} after trying all models and retries.")
            return {"cve_id": cve_id, "vulnerable_snippets": [], "repo_name_from_patch": repo_name_from_patch, "file_path_in_repo": None}

        max_follow_up_attempts = 2  # Increased to 2 attempts
        follow_up_attempt = 0
        json_parsed_successfully = False # Flag to track successful parsing

        while follow_up_attempt <= max_follow_up_attempts and not json_parsed_successfully: # Loop for follow-up attempts
            json_string = None # Initialize json_string here, will be used in follow-up prompt
            try:  # JSON parsing attempt
                vulnerable_snippets_raw = parse_gemini_json_output(
                    gemini_output, cve_id, follow_up_attempt + 1
                )
                vulnerable_snippets = []  # Clear vulnerable_snippets for each attempt
                for item in vulnerable_snippets_raw:  # type: ignore
                    if not isinstance(item, dict):
                        raise ValueError(f"'vulnerable_snippets_raw' item is not a dict: {item}")
                    vulnerable_snippets.append(item)
                json_parsed_successfully = True  # Parsing successful, set flag to exit loop
                break  # Exit the loop if parsing is successful

            except (json.JSONDecodeError, TypeError, ValueError) as e: # Catch parsing errors
                logger.error(
                    f"Error processing Gemini output for CVE {cve_id}, attempt {follow_up_attempt + 1}: {e}."
                )  # Include specific error in log
                if follow_up_attempt < max_follow_up_attempts: # Check if follow-up is allowed
                    follow_up_attempt += 1
                    follow_up_prompt_text = (
                        f"Your JSON response for CVE {cve_id} was invalid and could not be parsed. "
                    )
                    if isinstance(e, json.JSONDecodeError):
                        follow_up_prompt_text += (
                            "The error indicates a problem with the JSON syntax. "
                            "Please ensure the JSON is correctly formatted and valid. "
                        )
                    elif isinstance(e, (TypeError, ValueError)):
                        follow_up_prompt_text += (
                            "The error suggests the JSON structure is incorrect. "
                            "Ensure the JSON is a list of dictionaries, where each dictionary has 'file_path' and 'line_numbers' keys as described. "
                        )
                    if json_string: # Add JSON snippet only if json_string is not None and not empty
                        json_snippet = json_string[:200] + "..." if len(json_string) > 200 else json_string
                        follow_up_prompt_text += f"Here is a snippet of the invalid JSON you provided: `{json_snippet}`. "
                    follow_up_prompt_text += (
                        f"Specifically, the parsing error was: {e}. " # Include the parsing error in the follow-up prompt
                        "Please provide a **corrected**, **valid** JSON response, **strictly** enclosed in ```json and ``` markers. "  # Stronger emphasis on correction and markers
                        "Only return the JSON, without any extra text or comments outside the JSON block."
                    )
                    logger.info(f"Sending follow-up prompt to Gemini for CVE {cve_id}, attempt {follow_up_attempt}: {follow_up_prompt_text}")

                    # Send follow-up prompt to Gemini (using the same model as before)
                    current_model = genai.GenerativeModel(model_name) # Initialize model here, before the follow-up loop
                    gemini_output = None # Reset gemini_output for follow-up attempt

                    try:
                        response = current_model.generate_content(follow_up_prompt_text)
                        gemini_output = response.text
                        logger.debug(f"Gemini Follow-up Response for CVE {cve_id}, attempt {follow_up_attempt}:\n{gemini_output}")
                        if json_parsed_successfully: # Log successful follow-up output
                            logger.debug(
                                f"Gemini Follow-up Output (Successfully Parsed JSON) for CVE {cve_id}, attempt {follow_up_attempt}:\n{gemini_output}"
                            )
                    except Exception as follow_up_e:
                        logger.error(f"Error during Gemini follow-up attempt {follow_up_attempt} for CVE {cve_id}: {follow_up_e}")
                        break # If follow-up request fails, break the loop

                    if not gemini_output: # If no output from follow-up, break
                        logger.warning(f"No Gemini output received for follow-up attempt {follow_up_attempt} for CVE {cve_id}.")  # Changed to warning as it's not necessarily an error, just no response
                        logger.warning(f"Breaking follow-up loop for CVE {cve_id} due to empty Gemini output in follow-up attempt {follow_up_attempt}.") # Explicit log for loop break
                        break # No output from follow-up, break the loop to avoid infinite loop

                else: # Max follow-up attempts reached
                    logger.error(f"Max follow-up attempts reached for CVE {cve_id}. Parsing failed. Raw output:\n{gemini_output}")
                    break # Exit loop after max follow-ups

            if not json_parsed_successfully: # If parsing failed even after follow-ups (or no follow-up attempted)
                logger.warning(f"Failed to parse JSON from Gemini output for CVE {cve_id} after {follow_up_attempt} attempt(s). Raw output:\n{gemini_output}")
                vulnerable_snippets = [] # Ensure vulnerable_snippets is empty in case of parsing failure

    except ValueError as e:  # For repo path issues
        logger.warning(str(e))  # Log the specific error message
        # vulnerable_snippets remains empty

    except Exception as e:  # Catch any other unexpected exceptions
        logger.error(f"Unexpected error during Gemini analysis for {cve_id}: {e}")
        # vulnerable_snippets remains empty

    logger.debug(
        f"Vulnerable snippets after Gemini analysis for {cve_id}: {vulnerable_snippets}"
    )  # Log vulnerable_snippets before return

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

            introducing_commits_for_file: Dict[int, str] = (
                {}
            )  # line_number: commit_hash
            for line_number in snippet["line_numbers"]:
                try:
                    command_blame = [
                        "/usr/bin/git",
                        "blame",
                        "-L",
                        f"{line_number},{line_number}",
                        "--porcelain",  # for easier parsing
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
                        introducing_commits_for_file[line_number] = (
                            "blame_error"  # Indicate blame error
                        )
                    else:
                        blame_output = stdout_blame.decode("utf-8", errors="replace")
                        # Parse git blame porcelain output to get commit hash
                        commit_hash_match = re.search(
                            r"^([0-9a-f]{40}) ", blame_output, re.MULTILINE
                        )
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
                            introducing_commits_for_file[line_number] = (
                                "parse_error"  # Indicate parse error
                            )

                except subprocess.TimeoutExpired:
                    logger.error(
                        f"Git blame timed out for {cve_id}, file {snippet['file_path']}, line {line_number}"
                    )
                    introducing_commits_for_file[line_number] = (
                        "timeout_error"  # Indicate timeout
                    )
                except FileNotFoundError:
                    logger.error(
                        "Git blame command not found. Is Git installed and in PATH?"
                    )
                    introducing_commits_for_file[line_number] = (
                        "git_not_found"  # Indicate git not found
                    )
                except Exception as e:
                    logger.error(
                        f"Unexpected error during git blame for {cve_id}, file {snippet['file_path']}, line {line_number}: {e}"
                    )
                    introducing_commits_for_file[line_number] = (
                        "exception_error"  # Indicate exception
                    )

            vulnerable_snippets_with_commits.append(
                {**snippet, "introducing_commits": introducing_commits_for_file}
            )  # Add blame results
        vulnerable_snippets = vulnerable_snippets_with_commits  # Replace original snippets with enriched ones

    if not vulnerable_snippets:
        logger.info(
            f"No vulnerable snippets found in {patch_file_path.name if patch_file_path else 'unknown patch file'}"
        )

    return {
        "cve_id": cve_id,
        "vulnerable_snippets": vulnerable_snippets,
        "repo_name_from_patch": repo_name_from_patch,
        "file_path_in_repo": None,
    }


def analyze_patch_file(patch_file_path: Path, models):  # Added models parameter
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
        repo_path, repo_name_from_patch, cve_id, patch_file_path, models
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

    # Initialize Gemini models in main function
    gemini_models_to_try = [
        "gemini-2.0-flash",
        "gemini-2.0-flash-exp",
        "gemini-2.0-flash-lite",
        "gemini-1.5-flash-exp",
    ]
    try:
        genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
        logger.info("Gemini API configured successfully in main.")
    except Exception as e:
        logger.error(f"Error initializing Gemini model in main: {e}")

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
                    gemini_models_to_try,  # Pass list of Gemini models
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
                                for line_num, commit_hash in vuln_file_info[
                                    "introducing_commits"
                                ].items():
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
