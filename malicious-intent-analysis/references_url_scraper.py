import requests
from bs4 import BeautifulSoup
import sys
import time
import logging
from urllib.parse import urlparse
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def scrape_url(url):
    """
    Scrapes the content of a given URL and extracts text.

    Args:
        url (str): The URL to scrape.

    Returns:
        str: Extracted text content, or None if scraping fails.
    """
    try:
        logging.info(f"Scraping URL: {url}")
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        response = requests.get(
            url, headers=headers, timeout=15
        )  # Added timeout to prevent hanging
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

        soup = BeautifulSoup(response.content, "html.parser")

        # Extract all text content, you might need to refine this based on website structure
        text_content = " ".join(soup.stripped_strings)

        logging.info(f"Successfully scraped content from: {url}")
        return text_content

    except requests.exceptions.HTTPError as e:
        logging.error(f"HTTP Error scraping {url}: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection Error scraping {url}: {e}")
        return None
    except requests.exceptions.Timeout as e:
        logging.error(f"Timeout Error scraping {url}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Request Exception scraping {url}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error scraping {url}: {e}")
        return None


def save_content_to_file(url, content):
    """
    Saves the scraped content to a file.
    The filename is derived from the URL to make it unique and identifiable.

    Args:
        url (str): The original URL.
        content (str): The text content to save.
    """
    if content:
        parsed_url = urlparse(url)
        base_filename = parsed_url.netloc + parsed_url.path.replace("/", "_")
        safe_filename = "".join(
            x if x.isalnum() or x in "._-" else "_" for x in base_filename
        )  # Sanitize filename
        if not safe_filename:
            safe_filename = (
                "unnamed_content"  # Fallback if filename is empty after sanitization
            )
        filename = f"scraped_content/{safe_filename}.txt"  # Save to a subdirectory 'scraped_content'
        Path("scraped_content").as_posix().mkdir(
            parents=True, exist_ok=True
        )  # Ensure directory exists

        try:
            with open(
                filename, "w", encoding="utf-8"
            ) as f:  # Explicitly use utf-8 encoding
                f.write(content)
            logging.info(f"Content from {url} saved to {filename}")
        except IOError as e:
            logging.error(f"Error saving content to file {filename}: {e}")
    else:
        logging.warning(f"No content to save for URL: {url}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python references_url_scraper.py <url> [<url2> ...]")
        sys.exit(1)

    urls = sys.argv[1:]  # Get all URLs from command line arguments

    for url in urls:
        logging.info(f"Starting scraping process for URL: {url}")
        scraped_content = scrape_url(url)
        if scraped_content:
            save_content_to_file(url, scraped_content)
        time.sleep(1)  # Be respectful and add a delay between requests
    logging.info("Scraping process completed for all URLs.")
