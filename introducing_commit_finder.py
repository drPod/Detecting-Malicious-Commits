# This script uses the patches/ directory to find vulnerability introducing commits for each CVE.
import os
import re
from pathlib import Path
import logging
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from diff_parser import DiffParser

# Install diff-parser library: pip install diff-parser

PATCHES_DIR = Path("patches")
REPOS_DIR = Path("repos")
NVD_DATA_DIR = Path("nvd_data") # Add NVD data directory
LOG_FILE = Path("introducing_commit_finder.log")
OUTPUT_FILE = Path("vulnerable_code_snippets.json") # Output JSON file for results

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
logger.info(f"NVD data directory: {NVD_DATA_DIR.absolute()}")
logger.info(f"Output file: {OUTPUT_FILE.absolute()}")

def load_cve_data(cve_id: str) -> Optional[Dict[str, Any]]:
    """Load CVE data from JSON file."""
    cve_file = NVD_DATA_DIR / f"{cve_id}.json"
    if not cve_file.exists():
        logger.warning(f"CVE data file not found: {cve_file}")
        return None
    try:
        with open(cve_file, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        logger.error(f"Error decoding JSON from {cve_file}")
        return None


def analyze_patch_file(patch_file_path: Path):
    """
    Analyzes a patch file to identify vulnerable code snippets and generate git blame commands.
    """
    vulnerable_snippets = []
    git_blame_commands = []
    repo_path = None
    file_path_in_repo = None
    patch_content_str = ""
    cve_id = patch_file_path.name.split("_")[0]
    cve_data = load_cve_data(cve_id) # Load CVE data
    cwe_id = cve_data.get("vulnerability_details", {}).get("cwe_id") if cve_data else None # Extract CWE ID

    logger.info(f"Analyzing patch file: {patch_file_path.name}")
    try:
        with open(patch_file_path, "r") as f:
            patch_content_str = f.read() # Read entire patch content as string for diff_parser
            patch_content_lines = f.readlines() # Keep lines for manual parsing of filepath (if needed)
    except FileNotFoundError:
        logger.error(f"Patch file not found: {patch_file_path}")
        return {
            "cve_id": cve_id,
            "vulnerable_snippets": [],
            "git_blame_commands": [],
        }

    diff_header_line = next(
        (line for line in patch_content_lines if line.startswith("--- a/")), None # Use lines to find filepath
    )
    if diff_header_line: # Extract filepath from diff header
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

    try:
        diff = DiffParser().parse(patch_content_str) # Parse the patch content using diff-parser

        for file_diff in diff.files: # Iterate over each file changed in the patch
            if not file_diff.path: # Skip if no file path (shouldn't happen, but for robustness)
                logger.warning(f"No file path found in diff for {patch_file_path.name}")
                continue

            for hunk in file_diff.hunks: # Iterate over each hunk in the file
                vulnerable_code_block = [] # Store vulnerable code lines for current hunk
                context_lines_for_snippet = [] # Store context lines for the current vulnerable snippet

                # Iterate through lines in hunk.lines which are Line instances, not just strings
                for line_obj in hunk.lines:
                    if line_obj.removed: # Identify removed lines (potential vulnerability)
                        vulnerable_code_block.append(line_obj.content) # Add removed line content
                        context_lines = [] # Context for each vulnerable line

                        # Collect context lines (before and after the vulnerable line within the hunk)
                        line_index_in_hunk = hunk.lines.index(line_obj)
                        for context_idx in range(max(0, line_index_in_hunk - 2), min(line_index_in_hunk + 3, len(hunk.lines))):
                            context_line_obj = hunk.lines[context_idx]
                            if not context_line_obj.removed and not context_line_obj.added: # Get context lines (not added or removed)
                                context_lines.append(context_line_obj.content)
                        context_lines_for_snippet.extend(context_lines) # Add context lines to the current snippet's context

                        vulnerable_snippets.append(
                            {
                                "snippet": "\n".join(context_lines_for_snippet + vulnerable_code_block), # Vulnerable code + context
                                "cwe_id": cwe_id, # Include CWE ID
                                "cve_description": cve_data.get("vulnerability_details", {}).get("description") if cve_data else None,
                                # Access line number from line_obj, corrected to be original line number
                                "line_number": hunk.start_line + line_obj.number - 1 if line_obj.number else hunk.start_line
                            }
                        )
                    if file_path_in_repo and repo_path:
                        git_blame_commands.append(
                            f"cd {repo_path} && git blame <commit_hash> {file_path_in_repo} -L {hunk.start_line + line_obj.number -1},{hunk.start_line + line_obj.number -1}" # git blame command using line number from diff parser
                        )  # Replace <commit_hash> with a commit hash to run the command

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

    output_data = [] # List to store structured output

    for patch_file in patch_files:
        analysis_result = analyze_patch_file(patch_file)
        if analysis_result["vulnerable_snippets"]:
            logger.info(f"\n--- Analysis for {analysis_result['cve_id']} ---")
            logger.info("\nVulnerable Code Snippets:")
            for vuln_info in analysis_result["vulnerable_snippets"]:
                logger.info(f"Line: {vuln_info['line_number']}, CWE: {vuln_info['cwe_id']}")  # Print line number and CWE
                logger.info(vuln_info["snippet"])  # Print code snippet
                logger.info("---")

                output_data.append({ # Add to output data for each snippet
                    "cve_id": analysis_result['cve_id'],
                    "file_path": analysis_result['git_blame_commands'][0].split()[3] if analysis_result['git_blame_commands'] else None, # Extract file path from git blame command
                    "line_number": vuln_info['line_number'],
                    "cwe_id": vuln_info['cwe_id'],
                    "cve_description": vuln_info['cve_description'],
                    "code_snippet": vuln_info['snippet'],
                })

            logger.info("\nRecommended git blame commands (replace <commit_hash> and run in repo directory):")
            for command in analysis_result["git_blame_commands"]:
                logger.info(command)
            logger.info("\nTo determine the introducing commit:")
            logger.info("1. Run each git blame command in the corresponding repository.")
            logger.info("2. Examine the output of git blame to identify the commit hash that introduced the vulnerable lines.")
            logger.info("3. The earliest commit hash among all snippets is likely the vulnerability-introducing commit.")
        else:
            logger.info(f"No vulnerable snippets found in {patch_file.name}")

    with open(OUTPUT_FILE, 'w') as outfile: # Write output data to JSON file
        json.dump(output_data, outfile, indent=2)
    logger.info(f"Vulnerable code snippets saved to {OUTPUT_FILE}")

    logger.info("\nAnalysis completed.")
    logger.info(f"Script finished at {datetime.now().isoformat()}")


if __name__ == "__main__":
    main()
