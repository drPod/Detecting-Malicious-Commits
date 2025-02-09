import os
import json
import logging
import subprocess
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set
import signal
import sys
import threading
import shutil # Import shutil for deleting directories
from dotenv import load_dotenv

# Configuration
load_dotenv()  # Load environment variables
NVD_DATA_DIR = Path("nvd_data")
REPOS_DIR = Path("repos")
MIRROR_REPOS_DIR = Path("repos_mirror") # Directory containing mirror repos
STATE_FILE = Path("clone_state.json")
MAX_WORKERS = 5  # Conservative to avoid rate limits
GIT_TIMEOUT = 600  # Seconds for git operation timeout
GITHUB_TOKENS = [
    v for k, v in os.environ.items() if k.startswith("GITHUB_TOKEN_")
]  # Load all tokens

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("repo_cloner.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)
logger.info(f"Script starting at {datetime.now().isoformat()}")
logger.info(f"Repository directory: {REPOS_DIR.absolute()}")
logger.info(f"Mirror repository directory: {MIRROR_REPOS_DIR.absolute()}") # Log mirror repo dir
logger.info(f"Log file: {Path('repo_cloner.log').absolute()}")
logger.info(f"Loaded {len(GITHUB_TOKENS)} GitHub tokens")


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
        logger.info(f"Created repository directory at {REPOS_DIR.absolute()}")

        # Load existing state
        self.load_state()

        # Register signal handlers
        signal.signal(signal.SIGINT, self.handle_interrupt)
        signal.signal(signal.SIGTERM, self.handle_interrupt)

    def get_next_token(self):
        """Cycle through available GitHub tokens"""
        with self.lock:
            if not GITHUB_TOKENS:
                return ""
            token = GITHUB_TOKENS[self.current_token_idx]
            self.current_token_idx = (self.current_token_idx + 1) % len(GITHUB_TOKENS)
            return token

    def handle_interrupt(self, signum, frame):
        self.interrupted = True
        logger.warning("Interrupt received. Cleaning up and exiting...")

        # Terminate active processes
        for repo, process in self.active_processes.items():
            try:
                process.terminate()
                logger.info(f"Terminated process for {repo}")
            except Exception as e:
                logger.error(f"Error terminating {repo}: {str(e)}")

        # Shutdown executor
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)

        self.save_state()
        sys.exit(1)

    def load_state(self):
        try:
            if STATE_FILE.exists():
                with open(STATE_FILE) as f:
                    self.state = json.load(f)
                logger.info(f"Loaded state with {len(self.state)} entries")
                logger.debug(f"State contents: {json.dumps(self.state, indent=2)}")
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

    def get_repos_from_nvd(self) -> Set[str]:
        repos = set()
        logger.info(f"Scanning NVD data directory: {NVD_DATA_DIR.absolute()}")

        if not NVD_DATA_DIR.exists():
            logger.error(f"NVD data directory not found: {NVD_DATA_DIR}")
            return repos

        for json_file in NVD_DATA_DIR.glob("*.json"):
            logger.info(f"Processing NVD file: {json_file.name}")
            try:
                with open(json_file) as f:
                    data = json.load(f)
                    repo = data.get("github_data", {}).get("repository")
                    if repo:
                        if repo not in self.state:
                            repos.add(repo)
                            logger.debug(f"Found new repository: {repo}")
                        else:
                            logger.debug(
                                f"Skipping already processed repository: {repo}"
                            )
                    else:
                        logger.warning(f"No repository found in {json_file.name}")
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in file: {json_file}")
            except Exception as e:
                logger.error(f"Error processing {json_file}: {str(e)}")
        logger.info(f"Total new repositories found: {len(repos)}")
        return repos

    def clone_repo(self, repo: str) -> None:
        if self.interrupted:
            return

        repo_dir = REPOS_DIR / repo.replace("/", "_")
        mirror_repo_path = MIRROR_REPOS_DIR / repo.replace("/", "_") # Path to the local mirror repo

        with self.lock:
            if repo in self.state and self.state[repo] in ["success", "failed"]:
                logger.info(f"Skipping already processed repository: {repo}")
                return
            self.state[repo] = "started"
            self.save_state()

        try:
            # Check existing directory - now for the *working* repo directory
            if repo_dir.exists():
                git_dir = repo_dir / ".git"
                if git_dir.exists():
                    logger.info(f"Working repository {repo} already exists and appears valid. Skipping.")
                    with self.lock:
                        self.state[repo] = "success"
                    return
                else:
                    logger.warning(
                        f"Working repository directory {repo} exists but isn't a git repo. Removing..."
                    )
                    shutil.rmtree(repo_dir) # Use shutil.rmtree for directory removal
                    logger.info(f"Removed invalid working repository directory for {repo}")

            if not mirror_repo_path.exists() or not (mirror_repo_path / ".git").exists(): # Check if mirror repo exists
                logger.error(f"Mirror repository not found at: {mirror_repo_path}. Please ensure mirror repositories are in {MIRROR_REPOS_DIR}")
                with self.lock:
                    self.state[repo] = f"failed: mirror repo missing"
                return


            logger.info(f"Cloning working repository to: {repo_dir} from local mirror: {mirror_repo_path}") # Log working repo clone

            process = subprocess.Popen(
                ["git", "clone", str(mirror_repo_path), str(repo_dir)], # Clone from local mirror (no --mirror)
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            with self.lock:
                self.active_processes[repo] = process

            try:
                stdout, stderr = process.communicate(timeout=GIT_TIMEOUT)
                result = subprocess.CompletedProcess(
                    args=process.args,
                    returncode=process.returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                raise subprocess.TimeoutExpired(process.args, GIT_TIMEOUT)

            if result.returncode == 0:
                logger.info(f"Successfully cloned working repository {repo} from mirror.") # Log working repo clone success
                with self.lock:
                    self.state[repo] = "success"

                # --- Delete the mirror repository after successful working clone ---
                try:
                    logger.info(f"Deleting mirror repository: {mirror_repo_path}")
                    shutil.rmtree(mirror_repo_path) # Use shutil.rmtree to delete the mirror repo directory
                    logger.info(f"Mirror repository {repo} deleted successfully.")
                except Exception as e:
                    logger.error(f"Error deleting mirror repository {repo}: {e}")
                # --- End mirror repository deletion ---


            else:
                error = result.stderr.decode().strip()
                logger.error(f"Failed to clone working repository {repo} from mirror: {error}") # Log working repo clone failure
                logger.debug(f"Git output: {result.stdout.decode()}")
                with self.lock:
                    self.state[repo] = f"failed: {error}"

        except subprocess.TimeoutExpired:
            logger.error(f"Clone from mirror timed out for {repo}")
            with self.lock:
                self.state[repo] = "failed: timeout"
        except Exception as e:
            logger.error(f"Error cloning working repo from mirror {repo}: {str(e)}", exc_info=True)
            with self.lock:
                self.state[repo] = f"failed: {str(e)}"
        finally:
            with self.lock:
                if repo in self.active_processes:
                    del self.active_processes[repo]

        self.save_state()

    def process_repos(self):
        new_repos = self.get_repos_from_nvd()
        logger.info(f"Total repositories to process: {len(new_repos)}")

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS, thread_name_prefix="CloneWorker"
        ) as executor:
            self.executor = executor
            futures = {
                executor.submit(self.clone_repo, repo): repo for repo in new_repos
            }

            try:
                while futures and not self.interrupted:
                    done, _ = concurrent.futures.wait(
                        futures.keys(),
                        timeout=1,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )

                    for future in done:
                        repo = futures.pop(future)
                        try:
                            future.result()
                        except Exception as e:
                            logger.error(
                                f"Error processing {repo}: {str(e)}", exc_info=True
                            )
            except KeyboardInterrupt:
                self.handle_interrupt(None, None)
            finally:
                self.executor = None

        self.save_state()
        logger.info("Cloning process completed")

        # Summary
        success = sum(1 for s in self.state.values() if s.startswith("success"))
        failed = len(self.state) - success
        logger.info(f"Summary - Success: {success}, Failed: {failed}")
        logger.info(f"Script completed at {datetime.now().isoformat()}")


if __name__ == "__main__":
    manager = CloneManager()
    manager.process_repos()
