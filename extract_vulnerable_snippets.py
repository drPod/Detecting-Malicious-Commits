import os
import json
import subprocess
from pathlib import Path
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

# --- Configuration (consistent with introducing_commit_finder.py) ---
PATCHES_DIR = Path(os.environ.get("PATCHES_DIR", "patches"))
REPOS_DIR = Path(os.environ.get("REPOS_DIR", "repos"))
OUTPUT_FILE_DIR = Path(
    os.environ.get("OUTPUT_FILE_DIR", "vulnerable_code_snippets")
)  # Directory where introducing_commit_finder outputs JSON
EXTRACTED_SNIPPETS_DIR = Path(
    os.environ.get("EXTRACTED_SNIPPETS_DIR", "vulnerable_code_snippets_extracted")
)  # Output directory for extracted snippets
LOG_FILE = Path(
    os.environ.get("LOG_FILE", "extract_vulnerable_snippets.log")
)  # Log file for this script
CONTEXT_LINES_BEFORE = 2
CONTEXT_LINES_AFTER = 3
MAX_WORKERS = 12  # Define MAX_WORKERS for multithreading

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="w"),  # 'w' mode to clear log on start
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def extract_code_snippet(
    repo_path: Path, file_path: str, line_numbers: list[int]
) -> Optional[str]:
    """
    Extracts code snippet with context from a file at a specific commit.

    Args:
        repo_path: Path to the git repository.
        file_path: Path to the file within the repository.
        line_numbers: List of vulnerable line numbers.

    Returns:
        The code snippet as a string, or None if extraction fails.
    """
    full_file_path = repo_path / file_path
    if not full_file_path.exists() or not full_file_path.is_file():
        logger.warning(f"File not found at: {full_file_path.absolute()}")
        return None

    try:
        with open(full_file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        logger.error(f"UnicodeDecodeError reading file: {full_file_path.absolute()}")
        return None
    except Exception as e:
        logger.error(f"Error reading file {full_file_path.absolute()}: {e}")
        return None

    code_snippet = []
    start_line = max(0, min(line_numbers) - 1 - CONTEXT_LINES_BEFORE)
    end_line = min(len(lines), max(line_numbers) + CONTEXT_LINES_AFTER)

    for i in range(start_line, end_line):
        line_num = i + 1
        line = lines[i].rstrip("\n")  # remove trailing newline
        prefix = (
            "VULN> " if line_num in line_numbers else "      "
        )  # Mark vulnerable lines
        code_snippet.append(
            f"{prefix}{line_num:4d}: {line}"
        )  # Add line number and prefix

    return "\n".join(code_snippet)


def process_cve_json(json_file_path: Path):
    """
    Processes a single CVE JSON output file.

    Args:
        json_file_path: Path to the CVE JSON file.
    """
    try:
        with open(json_file_path, "r") as f:
            cve_data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON from {json_file_path}: {e}")
        return
    except FileNotFoundError:
        logger.error(f"JSON file not found: {json_file_path}")
        return

    cve_id = Path(json_file_path).stem  # Filename without extension is CVE ID
    logger.info(f"Processing CVE: {cve_id} from {json_file_path}")
    
    print(f"Processing JSON file: {json_file_path}")
    # --- Retrieve repo_name_from_patch from the top level of cve_data ---
    repo_name_from_patch = cve_data.get("repo_name_from_patch")
    if not repo_name_from_patch:
        logger.error(
            f"Repository name missing at the top level of JSON data for CVE: {cve_id} from {json_file_path}"
        )
        return  # Skip processing this CVE if repo_name is missing at CVE level

    print(f"  repo_name_from_patch: {repo_name_from_patch}")
    repo_path = REPOS_DIR / repo_name_from_patch  # Construct repo_path here, once per CVE
    print(f"  repo_path: {repo_path}")

    for snippet_info in cve_data:
        file_path = snippet_info.get("file_path")
        line_numbers = snippet_info.get("line_numbers")
        introducing_commits_dict = snippet_info.get("introducing_commits", {})

        if not file_path or not line_numbers or not introducing_commits_dict:
            logger.warning(
                f"Incomplete snippet info in {json_file_path}: {snippet_info}"
            )
            continue

        # Get the first commit hash from the dict (assuming line number as key)
        introducing_commit_hash = next(
            iter(introducing_commits_dict.values()), None
        )  # Get first value

        if not introducing_commit_hash or introducing_commit_hash in [
            "blame_error",
            "parse_error",
            "timeout_error",
            "git_not_found",
            "exception_error",
        ]:
            logger.warning(
                f"No valid introducing commit found for {cve_id}, file: {file_path}, lines: {line_numbers}. Skipping snippet extraction."
            )
            continue

        if not repo_path.exists() or not (repo_path / ".git").exists():  # Check repo_path validity only once per CVE
            logger.warning(
                f"Repository not found at: {repo_path}. Skipping snippet extraction for {cve_id}, file: {file_path}"
            )
            continue

        # --- Git Checkout ---
        try:
            command_checkout = [
                "/usr/bin/git",
                "checkout",
                "-f",
                introducing_commit_hash,
            ]  # -f to force checkout in case of conflicts
            logger.debug(
                f"Executing git checkout command: {' '.join(command_checkout)} in {repo_path}"
            )
            process_checkout = subprocess.Popen(
                command_checkout,
                cwd=repo_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout_checkout, stderr_checkout = process_checkout.communicate(
                timeout=60
            )  # Increased timeout to 60s

            if process_checkout.returncode != 0:
                error_message = stderr_checkout.decode("utf-8", errors="replace")
                logger.error(
                    f"Git checkout error for commit {introducing_commit_hash} in {repo_path} (CVE: {cve_id}, file: {file_path}): {error_message}"
                )
                continue  # Skip to next snippet if checkout fails
            else:
                logger.debug(
                    f"Successfully checked out commit {introducing_commit_hash} in {repo_path}"
                )

        except subprocess.TimeoutExpired:
            logger.error(
                f"Git checkout timed out for commit {introducing_commit_hash} in {repo_path} (CVE: {cve_id}, file: {file_path})"
            )
            continue
        except FileNotFoundError:
            logger.error("Git command not found. Is Git installed and in PATH?")
            continue
        except Exception as e:
            logger.error(
                f"Error during git checkout for {cve_id}, file {file_path}, commit {introducing_commit_hash}: {e}"
            )
            continue

        # --- Extract Code Snippet ---
        code_snippet_content = extract_code_snippet(repo_path, file_path, line_numbers)
        if code_snippet_content:
            print(f"    Snippet extracted for: {file_path}")
            # --- Save Snippet and Metadata ---
            cve_snippet_dir = EXTRACTED_SNIPPETS_DIR / "vulnerable" / cve_id
            cve_snippet_dir.mkdir(parents=True, exist_ok=True)
            snippet_filename = Path(file_path).name.replace(
                "/", "_"
            )  # Sanitize filename
            snippet_file_path = cve_snippet_dir / f"{snippet_filename}.txt"
            metadata_file_path = cve_snippet_dir / f"{snippet_filename}.json"

            try:
                with open(snippet_file_path, "w", encoding="utf-8") as outfile:
                    outfile.write(code_snippet_content)
                logger.info(f"Code snippet saved to: {snippet_file_path.absolute()}")
            except Exception as e:
                logger.error(
                    f"Error saving code snippet to {snippet_file_path.absolute()}: {e}"
                )

            metadata = {
                "cve_id": cve_id,
                "file_path": file_path,
                "line_numbers": line_numbers,
                "introducing_commit": introducing_commit_hash,
                "label": "vulnerable",  # Hardcoded label for now
            }
            try:
                with open(metadata_file_path, "w") as outfile:
                    json.dump(metadata, outfile, indent=2)
                logger.info(f"Metadata saved to: {metadata_file_path.absolute()}")
            except Exception as e:
                logger.error(
                    f"Error saving metadata to {metadata_file_path.absolute()}: {e}"
                )
        else:
            logger.warning(
                f"Failed to extract code snippet for {cve_id}, file: {file_path}, lines: {line_numbers}"
            )
            print(f"    Snippet extraction failed for: {file_path}")
        print("-" * 30)  # Separator for each snippet info

    print("=" * 50)  # Separator for each CVE JSON file
    logger.info(f"Finished processing CVE: {cve_id}")


def main():
    logger.info("Starting script to extract vulnerable code snippets...")
    EXTRACTED_SNIPPETS_DIR.mkdir(
        parents=True, exist_ok=True
    )  # Ensure output dir exists

    json_files = list(
        OUTPUT_FILE_DIR.glob("CVE-*.json")
    )  # Expecting filenames like CVE-YYYY-XXXX.json
    if not json_files:
        logger.warning(f"No CVE JSON files found in {OUTPUT_FILE_DIR.absolute()}.")
        return

    logger.info(
        f"Found {len(json_files)} JSON files to process in {OUTPUT_FILE_DIR.absolute()}."
    )

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(process_cve_json, json_files)

    logger.info("Finished processing CVE JSON files.")


if __name__ == "__main__":
    main()
