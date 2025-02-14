import os
import json
from pathlib import Path
import logging
from collections import defaultdict

# --- Configuration (consistent with extract_vulnerable_snippets.py) ---
OUTPUT_FILE_DIR = Path(
    os.environ.get("OUTPUT_FILE_DIR", "vulnerable_code_snippets")
)  # Directory where introducing_commit_finder outputs JSON
EXTRACTED_SNIPPETS_DIR = Path(
    os.environ.get("EXTRACTED_SNIPPETS_DIR", "vulnerable_code_snippets_extracted")
)  # Output directory for extracted snippets
LOG_FILE = Path(
    os.environ.get("LOG_FILE", "analyze_extracted_snippets_stats.log")
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, mode="w"),  # mode='w' to clear log on start
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)


def analyze_snippets_stats():
    """
    Analyzes extracted code snippets to generate statistics.
    """
    logger.info("Starting analysis of extracted code snippets...")
    snippet_counts_per_cve = defaultdict(int)
    snippet_counts_per_extension = defaultdict(int)
    total_snippets = 0

    vulnerable_dir = EXTRACTED_SNIPPETS_DIR / "vulnerable"
    if not vulnerable_dir.exists() or not vulnerable_dir.is_dir():
        logger.error(f"Vulnerable snippets directory not found: {vulnerable_dir.absolute()}")
        return

    for cve_dir in [d for d in vulnerable_dir.iterdir() if d.is_dir()]:
        cve_id = cve_dir.name
        snippet_files = list(cve_dir.glob("*.txt"))
        num_snippets_for_cve = len(snippet_files)
        snippet_counts_per_cve[cve_id] = num_snippets_for_cve
        total_snippets += num_snippets_for_cve

        for snippet_file in snippet_files:
            extension = snippet_file.suffix.lower()
            snippet_counts_per_extension[extension] += 1

    # Prepare stats report string
    stats_report = f"--- Extracted Snippets Statistics ---\n\n"
    stats_report += f"Total number of extracted snippets: {total_snippets}\n\n"
    stats_report += "Number of snippets per CVE:\n"
    for cve_id, count in snippet_counts_per_cve.items():
        stats_report += f"  {cve_id}: {count}\n"
    stats_report += "\n"
    stats_report += "Number of snippets per file extension:\n"
    for extension, count in snippet_counts_per_extension.items():
        stats_report += f"  {extension}: {count}\n"

    logger.info(stats_report)

    # Save stats to file
    stats_file_path = Path("analysis") / "extracted_snippets_stats.txt"
    stats_file_path.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
    try:
        with open(stats_file_path, "w") as f:
            f.write(stats_report)
        logger.info(f"Statistics report saved to: {stats_file_path.absolute()}")
    except Exception as e:
        logger.error(f"Error saving statistics report to {stats_file_path.absolute()}: {e}")

    logger.info("Finished analysis of extracted code snippets.")


def main():
    logger.info("Starting script to analyze extracted snippets...")
    analyze_snippets_stats()
    logger.info("Script finished.")


if __name__ == "__main__":
    main()
