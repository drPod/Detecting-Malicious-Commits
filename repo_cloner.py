import os
import json
import logging
import threading
import signal
import sys
from pathlib import Path
import datetime
from typing import Dict, Set
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from time import time, sleep
from dotenv import load_dotenv

# --- Configuration ---
load_dotenv()  # Load environment variables
NVD_DATA_DIR = Path("nvd_data")  # Directory for NVD data - configurable
REPOS_DIR = Path("repos")  # Directory for repositories - configurable
CLONE_STATE_FILE = Path("clone_state.json")  # State file - configurable
LOG_FILE = Path("repo_cloner.log")  # Log file - configurable
MAX_WORKERS = 14  # Number of threads for parallel cloning - configurable
GIT_TIMEOUT = 600  # Timeout for git commands in seconds - configurable
MAX_RETRIES = 1  # Maximum number of retries for git clone - configurable
RETRY_DELAY = 5  # Delay in seconds before retrying git clone - configurable


# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
logger.info(f"Script starting at {datetime.datetime.now().isoformat()}")
logger.info(f"Repository directory: {REPOS_DIR.absolute()}")
logger.info(f"Log file: {Path(LOG_FILE).absolute()}")


class CloneManager:
    def __init__(self):
        self.state: Dict[str, str] = {}  # {repo: status}
        self.lock = threading.RLock()
        self.repos_to_process: Set[str] = set()
        self.interrupted = False
        self.executor = None
        self.active_processes = {}
        self.current_token_idx = 0  # For token rotation

        # Setup directories
        REPOS_DIR.mkdir(parents=True, exist_ok=True)

        # Load existing state
        self.load_state()

        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)

    def handle_interrupt(self, signum, frame):
        self.interrupted = True
        logger.warning("Interrupt received. Cleaning up and exiting...")

        # Terminate active clones
        for repo, future in self.active_processes.items():
            try:
                future.cancel()
                logger.info(f"Cancelled clone for {repo}")
            except Exception as e:
                logger.error(f"Error cancelling {repo}: {str(e)}")

        self.save_state()
        sys.exit(1)

    def load_state(self):
        try:
            if CLONE_STATE_FILE.exists():
                with open(CLONE_STATE_FILE, "r") as f:
                    self.state = json.load(f)
                logger.info(f"Loaded state with {len(self.state)} entries")
            else:
                logger.info("No existing state file found")
        except Exception as e:
            logger.error(f"Error loading state: {str(e)}")

    def get_already_cloned_repos(self) -> Set[str]:
        """
        Identify already cloned repositories by checking for existing directories
        in the REPOS_DIR.
        """
        cloned_repo_dirs = set()
        try:
            for item in REPOS_DIR.iterdir():
                if item.is_dir():
                    cloned_repo_dirs.add(item.name)
            # Update state for already cloned repos
            with self.lock:
                for repo_dirname in cloned_repo_dirs:
                    # Reconstruct repo_url from dirname (reverse of repo_url.replace("/", "_"))
                    repo_url = repo_dirname.replace(
                        "_", "/"
                    )  # This is a simplification and might not be perfect
                    if repo_url not in self.state:  # Only add if not already in state
                        self.state[repo_url] = "success"
                self.save_state()  # Save state immediately after updating with existing repos
            logger.info(
                f"Found {len(cloned_repo_dirs)} existing repository directories in {REPOS_DIR}"
            )
        except Exception as e:
            logger.error(f"Error listing repository directories: {e}")
        return cloned_repo_dirs

    def save_state(self):
        with self.lock:
            try:
                with open(CLONE_STATE_FILE, "w") as f:
                    json.dump(self.state, f, indent=2)
                logger.debug("State file saved successfully")
            except Exception as e:
                logger.error(f"Error saving state: {str(e)}")

    def get_repos_from_nvd(self) -> Set[str]:
        """Extract unique repository names from NVD data files."""
        repos = set()
        nvd_files = list(NVD_DATA_DIR.glob("*.json"))
        logger.info(f"Scanning {len(nvd_files)} NVD files for repositories.")
        for nvd_file in nvd_files:
            try:
                with open(nvd_file, "r") as f:
                    vuln_data = json.load(f)
                    repo_name = vuln_data["github_data"]["repository"]
                    if repo_name:
                        repos.add(repo_name)
            except Exception as e:
                logger.error(f"Error reading NVD file {nvd_file}: {e}")
        logger.info(f"Found {len(repos)} unique repositories in NVD data.")
        return repos

    def clone_repo(self, repo_url: str) -> None:
        """Clones a single repository."""
        repo_name = repo_url.replace("/", "_")
        repo_path = REPOS_DIR / repo_name

        with self.lock:
            if repo_url in self.state and self.state[repo_url] in ["success", "failed"]:
                logger.info(f"Skipping already processed repository: {repo_url}")
                return
            self.state[repo_url] = "started"
            self.save_state()

        if repo_path.exists() and repo_path.is_dir():
            logger.info(f"Repository directory already exists: {repo_url}")
            with self.lock:
                self.state[repo_url] = "success"
                self.save_state()
            return

        retry_count = 0
        while retry_count <= MAX_RETRIES and not self.interrupted:
            start_time = time()
            try:
                logger.info(f"Cloning repository: {repo_url} to {repo_path}")
                command = [
                    "/usr/bin/git",
                    "clone",
                    f"https://github.com/{repo_url}",
                    str(repo_path),
                ]
                env = os.environ.copy()  # Copy the current environment
                env["GIT_TERMINAL_PROMPT"] = "0"  # Disable git prompt
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    # timeout=GIT_TIMEOUT,
                )
                process.env = env  # Apply modified env to subprocess
                self.active_processes[repo_url] = process  # Track active process
                stdout, stderr = process.communicate()
                del self.active_processes[repo_url]  # Remove after completion

                if process.returncode == 0:
                    logger.info(f"Successfully cloned repository: {repo_url}")
                    with self.lock:
                        self.state[repo_url] = "success"
                        self.save_state()
                    return
                else:
                    error_message = stderr.decode("utf-8", errors="replace").strip()
                    logger.error(
                        f"Failed to clone repository {repo_url} with return code {process.returncode}: {error_message}"
                    )
                    logger.debug(f"Git clone output: {stdout.decode()}")
                    retry_count += 1
                    sleep(RETRY_DELAY)

            except subprocess.TimeoutExpired:
                logger.error(f"Timeout cloning repository: {repo_url}")
                retry_count += 1
                sleep(RETRY_DELAY)
            except FileNotFoundError:
                logger.error("Git command not found. Is Git installed and in PATH?")
                with self.lock:
                    self.state[repo_url] = "failed: Git not found"
                    self.save_state()
                return
            except Exception as e:
                logger.error(f"Error cloning repository {repo_url}: {e}")
                retry_count += 1
                sleep(RETRY_DELAY)
            finally:
                clone_duration = time() - start_time
                logger.info(
                    f"Clone attempt for {repo_url} took {clone_duration:.2f} seconds."
                )
                if self.interrupted:
                    logger.warning(
                        f"Clone process interrupted for {repo_url} after {retry_count} retries."
                    )
                    break  # Exit retry loop if interrupted

        with self.lock:
            self.state[repo_url] = f"failed after {MAX_RETRIES} retries"
            self.save_state()

    def process_repos(self):
        """Main function to process and clone repositories."""
        self.repos_to_process = self.get_repos_from_nvd()
        already_cloned_dirs = self.get_already_cloned_repos()
        repos_to_clone = [
            repo
            for repo in self.repos_to_process
            if repo.replace("/", "_") not in already_cloned_dirs
            and repo not in self.state
        ]

        logger.info(
            f"Identified {len(repos_to_clone)} repositories to clone after checking existing directories."
        )

        if not repos_to_clone:
            logger.info("No new repositories to clone.")
            return

        logger.info(f"Found {len(repos_to_clone)} new repositories to clone.")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            self.executor = executor  # Assign executor to self for interrupt handling
            futures = {
                executor.submit(self.clone_repo, repo): repo for repo in repos_to_clone
            }
            with tqdm(total=len(futures), desc="Cloning Repositories") as pbar:
                for future in as_completed(futures):
                    repo = futures[future]
                    try:
                        future.result()  # Get result to raise any exceptions
                    except Exception as e:
                        logger.error(f"Task for {repo} raised an exception: {e}")
                    finally:
                        pbar.update(1)
        self.executor = None  # Reset executor after use

        logger.info("Repository cloning process completed.")
        # Summary
        success = sum(1 for s in self.state.values() if s == "success")
        failed = len(self.state) - success
        logger.info(f"Summary - Success: {success}, Failed: {failed}")
        logger.info(f"Script completed at {datetime.datetime.now().isoformat()}")


def main():
    cloner = CloneManager()
    cloner.process_repos()
    print("\nRepository cloning complete! Check logs for details.")


if __name__ == "__main__":
    main()
