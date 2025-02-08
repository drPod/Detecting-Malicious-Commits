import os
import json
import logging
import requests
from pathlib import Path
from tqdm import tqdm
from dotenv import load_dotenv
import threading
import signal
import sys
from typing import Dict, List, Set
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

# Configuration
load_dotenv()  # Load environment variables
NVD_DATA_DIR = Path("nvd_data")
REPOS_DIR = Path("repos")
PATCHES_DIR = Path("patches")
STATE_FILE = Path("patch_state.json")  # Separate state file for this script
CLONE_STATE_FILE = Path("clone_state.json") # Clone state file
MAX_WORKERS = 10  # Conservative to avoid rate limits

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("patch_downloader.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
logger.info(f"Script starting at {datetime.now().isoformat()}")
logger.info(f"Patch directory: {PATCHES_DIR.absolute()}")
logger.info(f"Log file: {Path('patch_downloader.log').absolute()}")


class PatchDownloader:
    def __init__(self):
        self.state: Dict[str, str] = {}  # {cve_id: status}
        self.lock = threading.RLock()
        self.interrupted = False
        self.active_downloads = {}

        # Setup directories
        PATCHES_DIR.mkdir(parents=True, exist_ok=True)

        # Load existing state
        self.load_state()

        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)

    def handle_interrupt(self, signum, frame):
        self.interrupted = True
        logger.warning("Interrupt received. Cleaning up and exiting...")

        # Terminate active downloads
        for cve_id, future in self.active_downloads.items():
            try:
                future.cancel()
                logger.info(f"Cancelled download for {cve_id}")
            except Exception as e:
                logger.error(f"Error cancelling {cve_id}: {str(e)}")

        self.save_state()
        sys.exit(1)

    def load_state(self):
        try:
            if STATE_FILE.exists():
                with open(STATE_FILE) as f:
                    self.state = json.load(f)
                logger.info(f"Loaded state with {len(self.state)} entries")
            else:
                logger.info("No existing state file found")
        except Exception as e:
            logger.error(f"Error loading state: {str(e)}")

    def save_state(self):
        with self.lock:
            try:
                with open(STATE_FILE, "w") as f:
                    json.dump(self.state, f, indent=2)
                logger.debug("State file saved successfully")
            except Exception as e:
                logger.error(f"Error saving state: {str(e)}")

    def download_patch(self, vuln_ Dict) -> None:
        """Downloads the patch file for a given vulnerability."""
        if not vuln_data or not vuln_data["github_data"]["patch_url"]:
            return

        cve_id = vuln_data["cve_id"]
        patch_url = vuln_data["github_data"]["patch_url"]
        owner_repo = vuln_data["github_data"]["repository"].replace("/", "_")
        patch_filename = f"{cve_id}_{owner_repo}.patch"
        patch_filepath = PATCHES_DIR / patch_filename

        with self.lock:
            if cve_id in self.state and self.state[cve_id] in ["success", "failed"]:
                logger.info(f"Skipping already processed patch: {patch_filename}")
                return
            self.state[cve_id] = "started"
            self.save_state()

        # Check if the patch file already exists
        if patch_filepath.exists():
            logger.info(f"Patch file already exists: {patch_filename}")
            with self.lock:
                self.state[cve_id] = "success"
                self.save_state()
            return

        try:
            logger.info(f"Downloading patch file: {patch_url}")
            response = requests.get(patch_url, stream=True)
            response.raise_for_status()

            with open(patch_filepath, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            logger.info(f"Successfully downloaded patch file: {patch_filename}")
            with self.lock:
                self.state[cve_id] = "success"
                self.save_state()

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download patch file {patch_url}: {e}")
            with self.lock:
                self.state[cve_id] = f"failed: {str(e)}"
                self.save_state()
        except Exception as e:
            logger.error(f"Error processing {patch_url}: {str(e)}")
            with self.lock:
                self.state[cve_id] = f"failed: {str(e)}"
                self.save_state()

    def process_data(self):
        """Main function to find CVEs with patch URLs and download them."""
        cve_files = list(NVD_DATA_DIR.glob("*.json"))
        logger.info(f"Found {len(cve_files)} CVE files to process.")

        # Load clone state
        try:
            with open(CLONE_STATE_FILE, "r") as f:
                clone_state = json.load(f)
        except FileNotFoundError:
            logger.error(f"{CLONE_STATE_FILE} not found")
            return

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {}
            for cve_file in cve_files:
                try:
                    with open(cve_file, "r") as f:
                        vuln_data = json.load(f)
                    repo = vuln_data["github_data"]["repository"]
+                   if clone_state.get(repo, "") == "success" and vuln_data["github_data"]["patch_url"]:
+                        future = executor.submit(self.download_patch, vuln_data)
+                        futures[vuln_data["cve_id"]] = future
+                except Exception as e:
+                    logger.error(f"Error loading or processing {cve_file}: {e}")
+
+            with tqdm(total=len(futures), desc="Downloading Patches") as pbar:
+                for cve_id, future in futures.items():
+                    try:
+                        future.result()
+                    except Exception as e:
+                        logger.error(f"Failed to download patch for {cve_id}: {e}")
+                    finally:
+                        pbar.update(1)
+
+        logger.info("Patch downloading process completed.")
+        # Summary
+        success = sum(1 for s in self.state.values() if s == "success")
+        failed = len(self.state) - success
+        logger.info(f"Summary - Success: {success}, Failed: {failed}")
+        logger.info(f"Script completed at {datetime.now().isoformat()}")
+
+
+def main():
+    downloader = PatchDownloader()
+    downloader.process_data()
+    print("\nPatch downloading complete! Check logs for details.")
+
+
+if __name__ == "__main__":
+    main()
