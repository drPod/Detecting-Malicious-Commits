# This script uses the patches/ directory to find vulnerability introducing commits for each CVE.
import os
import subprocess
from pathlib import Path
import logging

# Configuration
PATCHES_DIR = Path("patches")
REPOS_DIR = Path("repos")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def find_introducing_commit(patch_file_path: Path):
    """
    Attempts to find the introducing commit for a vulnerability given a patch file.
    """
    patch_filename = patch_file_path.name
    parts = patch_filename.replace(".patch", "").split("_", 2) # Expecting CVE-YYYY-XXXXX_owner_repo.patch
    if len(parts) != 3:
        logger.error(f"Invalid patch filename format: {patch_filename}")
        return None
    cve_id, owner_repo_name = parts[0], parts[1] + "/" + parts[2]
    repo_path = REPOS_DIR / owner_repo_name.replace("/", "_")

    if not repo_path.exists():
        logger.error(f"Repository directory not found: {repo_path}")
        return None

    try:
        # Apply patch in reverse to revert the fix
        subprocess.run(["git", "apply", "-R", str(patch_file_path)], cwd=str(repo_path), check=True, capture_output=True)
        # Get the commit hash after reversing the patch
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(repo_path), capture_output=True, text=True, check=True)
        introducing_commit_hash = result.stdout.strip()
        return {"cve_id": cve_id, "repository": owner_repo_name, "introducing_commit": introducing_commit_hash}
    except subprocess.CalledProcessError as e:
        logger.error(f"Error processing {patch_filename} in {owner_repo_name}: {e.stderr.decode()}")
        return None

if __name__ == "__main__":
    for patch_file in PATCHES_DIR.glob("*.patch"):
        result = find_introducing_commit(patch_file)
        if result:
            print(f"CVE: {result['cve_id']}, Repository: {result['repository']}, Introducing Commit: {result['introducing_commit']}")
