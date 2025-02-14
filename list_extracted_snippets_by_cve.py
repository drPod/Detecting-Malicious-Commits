import os
import json
from pathlib import Path
import logging

# --- Configuration (consistent with extract_vulnerable_snippets.py) ---
EXTRACTED_SNIPPETS_DIR = Path(
    os.environ.get("EXTRACTED_SNIPPETS_DIR", "vulnerable_code_snippets_extracted")
)  # Output directory for extracted snippets
LOG_FILE = Path(
    os.environ.get("LOG_FILE", "list_extracted_snippets_by_cve.log")
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


def list_snippets_by_cve():
    """
    Lists extracted code snippets grouped by CVE ID.
    """
    logger.info("Starting listing of extracted snippets by CVE...")
    listing_output = ""

    vulnerable_dir = EXTRACTED_SNIPPETS_DIR / "vulnerable"
    if not vulnerable_dir.exists() or not vulnerable_dir.is_dir():
        logger.error(f"Vulnerable snippets directory not found: {vulnerable_dir.absolute()}")
        return

    # Get all CVE directories and sort them
    cve_dirs = sorted([d for d in vulnerable_dir.iterdir() if d.is_dir()])
    
    if not cve_dirs:
        listing_output = "No CVE directories found.\n"
    else:
        listing_output = "=== Extracted Snippets by CVE ===\n\n"
        for cve_dir in cve_dirs:
            cve_id = cve_dir.name
            listing_output += f"  CVE ID: {cve_id}\n"
            for item in sorted(cve_dir.iterdir()):
                if item.is_file():
                    listing_output += f"    - {item.name} (Path: {item.absolute()})\n"
            listing_output += "\n"

    logger.info(listing_output)

    # Save listing to file
    listing_file_path = Path("analysis") / "extracted_snippets_list.txt"
    listing_file_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(listing_file_path, "w") as f:
            f.write(listing_output)
        logger.info(f"Snippet listing saved to: {listing_file_path.absolute()}")
    except Exception as e:
        logger.error(f"Error saving snippet listing to {listing_file_path.absolute()}: {e}")

    logger.info("Finished listing of extracted code snippets.")


def main():
    logger.info("Starting script to list extracted snippets by CVE...")
    list_snippets_by_cve()
    logger.info("Script finished.")


if __name__ == "__main__":
    main()
