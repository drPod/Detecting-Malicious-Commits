# This script uses the patches/ directory to find vulnerability introducing commits for each CVE.
import os
import re
from pathlib import Path
import logging
from datetime import datetime

PATCHES_DIR = Path("patches")
REPOS_DIR = Path("repos")
LOG_FILE = Path("introducing_commit_finder.log")

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
logger.info(f"Script starting at {datetime.now().isoformat()}")
logger.info(f"Patch directory: {PATCHES_DIR.absolute()}")
logger.info(f"Repository directory: {REPOS_DIR.absolute()}")
logger.info(f"Log file: {LOG_FILE.absolute()}")


def analyze_patch_file(patch_file_path: Path):
    """
    Analyzes a patch file to identify vulnerable code snippets and generate git blame commands.
    """
    vulnerable_snippets = []
    git_blame_commands = []
    repo_path = None
    file_path_in_repo = None

    cve_id = patch_file_path.name.split("_")[0]

    logger.info(f"Analyzing patch file: {patch_file_path.name}")
    try:
        with open(patch_file_path, "r") as f:
            patch_content = f.readlines()
    except FileNotFoundError:
        logger.error(f"Patch file not found: {patch_file_path}")
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "git_blame_commands": [],
        }

    diff_header_line = next(
        (line for line in patch_content if line.startswith("--- a/")), None
    )
    if diff_header_line:
        file_path_in_patch = diff_header_line.split("--- a/")[1].strip()
        file_path_in_repo = file_path_in_patch
        repo_name_from_patch = patch_file_path.name.replace(cve_id + "_", "").replace(
            ".patch", ""
        )
        repo_path = REPOS_DIR / repo_name_from_patch  # Correctly use REPOS_DIR
    else:
        logger.warning(
            f"No diff header found in {patch_file_path.name}. Skipping file path extraction."
        )
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "git_blame_commands": [],
        }

    hunks = []
    current_hunk = None

    try:
        for line in patch_content:
            if line.startswith("@@"):
                if current_hunk:
                    hunks.append(current_hunk)
                current_hunk = {"lines": [], "header": line.strip()}
            elif current_hunk is not None:
                current_hunk["lines"].append(line)
        if current_hunk:
            hunks.append(current_hunk)

        for hunk in hunks:
            vulnerable_code_block = []
            start_line_number = int(
                hunk["header"]
                .split("@@")[1]
                .strip()
                .split(" ")[0]
                .split(",")[0]
                .replace("-", "")
            )
            original_line_offset = 0  # Track line numbers in the original file
            added_line_offset = 0  # Track line numbers in the new file
            for line in hunk["lines"]:
                if line.startswith("-"):
                    vulnerable_code_block.append(line.strip())
                    context_lines = []
                    context_lines.append(line.strip())
                    # Add a few lines of context from the hunk
                    line_index = hunk["lines"].index(line)
                    for context_idx in range(
                        max(0, line_index - 2), min(line_index + 3, len(hunk["lines"]))
                    ):
                        if not hunk["lines"][context_idx].startswith("-") and not hunk[
                            "lines"
                        ][context_idx].startswith("+"):
                            context_lines.append(hunk["lines"][context_idx].strip())

                    is_modified = (
                        False  # Check if it's a modification (has corresponding + line)
                    )
                    for next_line in hunk["lines"][
                        line_index + 1 :
                    ]:  # Check lines after the '-' line in the hunk
                        if (
                            next_line.startswith("+")
                            and line[1:].strip() == next_line[1:].strip()
                        ):  # Basic check if content is similar, could be improved
                            is_modified = True
                            break

                    if (
                        is_modified or True
                    ):  # Consider it vulnerable if modified or always (for now, to not miss pure removals)
                        vulnerable_snippets.append(
                            {
                                "snippet": "\n".join(context_lines),
                                "line_number": start_line_number
                                + original_line_offset,  # Line number in original file
                            }
                        )
                    if file_path_in_repo and repo_path:
                        git_blame_commands.append(
                            f"cd {repo_path} && git blame <commit_hash> {file_path_in_repo} -L {start_line_number + original_line_offset},{start_line_number + original_line_offset}"
                        )  # Replace <commit_hash> with a commit hash to run the command
                if not line.startswith(
                    "+"
                ):  # Count original lines (lines starting with '-' or ' ')
                    original_line_offset += 1
                if not line.startswith(
                    "-"
                ):  # Count lines in the patched file (lines starting with '+' or ' ')
                    added_line_offset += 1
    except Exception as e:
        logger.error(f"Error parsing patch hunk in {patch_file_path.name}: {e}")
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "git_blame_commands": [],
        }  # Return empty lists in case of error

    return {
        "cve_id": cve_id,
        "vulnerable_snippets": vulnerable_snippets,
        "git_blame_commands": git_blame_commands,
    }


def main():
    patch_files = list(PATCHES_DIR.glob("*.patch"))
    if not patch_files:
        logger.warning(
            f"No patch files found in {PATCHES_DIR}. Please run patch_downloader.py first."
        )
        return

    logger.info(f"Analyzing {len(patch_files)} patch files from {PATCHES_DIR}...")

    for patch_file in patch_files:
        analysis_result = analyze_patch_file(patch_file)
        if analysis_result["vulnerable_snippets"]:
            logger.info(f"\n--- Analysis for {analysis_result['cve_id']} ---")
            logger.info("\nVulnerable Code Snippets:")
            for vuln_info in analysis_result["vulnerable_snippets"]:
                logger.info(f"Line: {vuln_info['line_number']}")  # Print line number
                logger.info(vuln_info["snippet"])  # Print code snippet
                logger.info("---")

            logger.info(
                "\nRecommended git blame commands (replace <commit_hash> and run in repo directory):"
            )
            for command in analysis_result["git_blame_commands"]:
                logger.info(command)
            logger.info("\nTo determine the introducing commit:")
            logger.info(
                "1. Run each git blame command in the corresponding repository."
            )
            logger.info(
                "2. Examine the output of git blame to identify the commit hash that introduced the vulnerable lines."
            )
            logger.info(
                "3. The earliest commit hash among all snippets is likely the vulnerability-introducing commit."
            )
        else:
            logger.info(f"No vulnerable snippets found in {patch_file.name}")

    logger.info("\nAnalysis completed.")
    logger.info(f"Script finished at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
