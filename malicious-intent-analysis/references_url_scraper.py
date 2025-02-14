import requests
from bs4 import BeautifulSoup
import sys
import time
import logging
from urllib.parse import urlparse
from pathlib import Path
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_WORKERS = 12
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds
DELAY_BETWEEN_REQUESTS = 1  # seconds, delay after each request to be respectful

INDEX_FILE = "scraped_content_index.json"
SCRAPED_CONTENT_DIR = "scraped_content"

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

def load_index():
    """Loads the index from JSON file, or returns an empty dict if file not found."""
    try:
        with open(INDEX_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_index(index_data):
    """Saves the index data to JSON file."""
    Path(SCRAPED_CONTENT_DIR).mkdir(parents=True, exist_ok=True) # Ensure directory exists before saving index
    with open(INDEX_FILE, 'w') as f:
        json.dump(index_data, f, indent=4)


def scrape_url(url, cve_id):
    """
    Scrapes the content of a given URL and extracts text with retry mechanism.

    Args:
        url (str): The URL to scrape.
        cve_id (str): The CVE ID associated with the URL.

    Returns:
        str: Extracted text content, or None if scraping fails after retries.
    """
    for attempt in range(MAX_RETRIES + 1):
        try:
            logging.info(f"CVE: {cve_id} - Scraping URL: {url} (Attempt {attempt+1}/{MAX_RETRIES+1})")
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, 'html.parser')
            text_content = ' '.join(soup.stripped_strings)

            logging.info(f"CVE: {cve_id} - Successfully scraped content from: {url}")
            return text_content

        except requests.exceptions.HTTPError as e:
            logging.error(f"CVE: {cve_id} - HTTP Error scraping {url} (Attempt {attempt+1}/{MAX_RETRIES+1}): {e}")
        except requests.exceptions.ConnectionError as e:
            logging.error(f"CVE: {cve_id} - Connection Error scraping {url} (Attempt {attempt+1}/{MAX_RETRIES+1}): {e}")
        except requests.exceptions.Timeout as e:
            logging.error(f"CVE: {cve_id} - Timeout Error scraping {url} (Attempt {attempt+1}/{MAX_RETRIES+1}): {e}")
        except requests.exceptions.RequestException as e:
            logging.error(f"CVE: {cve_id} - Request Exception scraping {url} (Attempt {attempt+1}/{MAX_RETRIES+1}): {e}")
        except Exception as e:
            logging.error(f"CVE: {cve_id} - Unexpected error scraping {url} (Attempt {attempt+1}/{MAX_RETRIES+1}): {e}")

        if attempt < MAX_RETRIES:
            time.sleep(RETRY_DELAY) # Wait before retrying
        else:
            logging.error(f"CVE: {cve_id} - Max retries reached for URL: {url}. Scraping failed.")
            return None
    return None # Should not reach here, but for clarity


def save_content_to_file(url, content, cve_id):
    """
    Saves the scraped content to a file and updates the index.

    Args:
        url (str): The original URL.
        content (str): The text content to save.
        cve_id (str): The CVE ID associated with the URL.
    """
    if content:
        parsed_url = urlparse(url)
        base_filename = parsed_url.netloc + parsed_url.path.replace("/", "_")
        safe_filename = "".join(x if x.isalnum() or x in "._-" else "_" for x in base_filename)
        if not safe_filename:
            safe_filename = "unnamed_content"
        filename = f"{SCRAPED_CONTENT_DIR}/{safe_filename}.txt"
        Path(SCRAPED_CONTENT_DIR).mkdir(parents=True, exist_ok=True)

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
                logging.info(f"CVE: {cve_id} - Content from {url} saved to {filename}")

                # Update index and save (only if file writing was successful)
                index_data = load_index()
                index_data.setdefault(cve_id, []).append({'url': url, 'filename': filename})
                save_index(index_data)

        except IOError as e:
            logging.error(f"CVE: {cve_id} - Error saving content to file {filename}: {e}")

    else:
        logging.warning(f"CVE: {cve_id} - No content to save for URL: {url}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python references_url_scraper.py <url1> <cve_id1> [<url2> <cve_id2> ...]")
        sys.exit(1)

    url_cve_pairs = []
    args = sys.argv[1:]
    if len(args) % 2 != 0:
        print("Error: URLs and CVE IDs must be provided in pairs.")
        sys.exit(1)

    for i in range(0, len(args), 2):
        url = args[i]
        cve_id = args[i+1]
        url_cve_pairs.append((url, cve_id))

    logging.info(f"Starting scraping process for {len(url_cve_pairs)} URL(s) with {MAX_WORKERS} workers.")

    def process_url(url_cve_pair):
        """Processes a single URL and CVE ID pair."""
        url, cve_id = url_cve_pair
        scraped_content = scrape_url(url, cve_id)
        if scraped_content:
            save_content_to_file(url, scraped_content, cve_id)
        time.sleep(DELAY_BETWEEN_REQUESTS) # Be respectful

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_url, pair) for pair in url_cve_pairs]
        for future in as_completed(futures):
            future.result() # To catch any exceptions from threads

    logging.info("Scraping process completed for all URLs.")
