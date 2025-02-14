import json
from pathlib import Path
import google.generativeai as genai
import os
from dotenv import load_dotenv
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import google.api_core.exceptions
import google.generativeai.types.generation_types
from tqdm import tqdm
from references_url_scraper import load_index, SCRAPED_CONTENT_DIR

# Define max workers in a variable
MAX_WORKERS = 12

# Load environment variables from .env file
load_dotenv()

# Setup logging
logging.basicConfig(
    filename="malicious_intent_analyzer.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logging.debug("Starting malicious intent analyzer script.")

# Configure Gemini API - replace with your actual API key or setup
# WARNING: Disabling safety settings can lead to the model generating harmful content.
#          This is generally NOT recommended and should only be done with extreme caution
#          and for specific use cases where you understand and accept the risks.
#          It is crucial to use the API responsibly and ethically.
#
#          If you proceed with disabling safety settings, ensure you have mechanisms
#          in place to review and filter the generated content before it is used or displayed.
#
#          Use BLOCK_NONE with extreme caution and at your own risk.
#          Consider BLOCK_ONLY_HIGH or BLOCK_MEDIUM_AND_ABOVE for a safer approach.

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel(
    "gemini-pro",
    safety_settings=[  # Disable all safety filters - USE WITH EXTREME CAUTION
        {
            "category": genai.types.HarmCategory.HARM_CATEGORY_HARASSMENT,
            "threshold": genai.types.HarmBlockThreshold.BLOCK_NONE,
        },
        {
            "category": genai.types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
            "threshold": genai.types.HarmBlockThreshold.BLOCK_NONE,
        },
        {
            "category": genai.types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
            "threshold": genai.types.HarmBlockThreshold.BLOCK_NONE,
        },
        {
            "category": genai.types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
            "threshold": genai.types.HarmBlockThreshold.BLOCK_NONE,
        },
    ],
)


def analyze_with_gemini(
    cve_id: str, cve_description: str, references: list, scraped_content_index
):
    """
    Analyzes CVE description and references using Gemini to determine malicious intent.
    """
    logging.debug(
        f"CVE: {cve_id} - Analyzing CVE description for malicious intent."
    )  # Log before prompt construction

    prompt_text = "Analyze the following CVE description and associated references to determine if the vulnerability was likely introduced with malicious intent. "
    prompt_text += "\n\n"
    prompt_text += "CVE Description: " + cve_description + ". "
    prompt_text += "\n\n"
    prompt_text += "References: " + "\n"
    for ref in references:
        tags_str = ", ".join(ref.get("tags", []))
        ref_url = ref.get("url", "N/A")
        prompt_text += f"- URL: {ref_url}, Tags: [{tags_str}]\n"

        # Include scraped content if available
        if cve_id in scraped_content_index:
            for item in scraped_content_index[cve_id]:
                if item["url"] == ref_url:
                    content_filename = item["filename"]
                    content_path = Path(content_filename)
                    if content_path.exists():
                        try:
                            with open(
                                content_path, "r", encoding="utf-8"
                            ) as content_file:
                                scraped_text = content_file.read()
                                prompt_text += f"\n---\nScraped Content from {ref_url}:\n{scraped_text}\n---\n"
                        except Exception as e:
                            logging.error(
                                f"CVE: {cve_id} - Error reading scraped content file {content_filename}: {e}"
                            )
    prompt_text += (
        "Consider factors such as: Keywords in the description suggesting intentional "
        "backdoor, sabotage, or malicious code. References pointing to exploit code, "
        "discussions of malicious use, or indicators of compromise. Tags like 'exploit', "
        "'malware', 'backdoor' in the references."
    )
    prompt_text += "Respond with a JSON object in the following format:\n"
    prompt_text += "In the 'reason' field, briefly explain your reasoning. "
    prompt_text += "Specifically, mention any keywords from the CVE description or tags from the references that support your decision. "
    prompt_text += (
        "Summarize the logic you used to determine if malicious intent is likely.\n"
    )
    prompt_text += "```json\n"
    prompt_text += "{\n"
    prompt_text += '"malicious_intent_likely": true/false,\n'
    prompt_text += '"reason": "brief explanation of your reasoning"\n'
    prompt_text += "}\n"
    prompt_text += "```\n"
    prompt_text += "Example of a good 'reason': 'Keywords like 'backdoor' and reference tags like 'malware' suggest malicious intent. The description mentions intentional code modification for unauthorized access.'\n"
    prompt_text += "Ensure your response is enclosed in ```json and ``` markers."

    json_retry_count = 0
    max_json_retries = 0  # Only retry once if JSON is invalid
    retry_count = 0
    max_retries = 10
    while retry_count <= max_retries:
        logging.debug(f"CVE: {cve_id} - Gemini Prompt: {prompt_text}")
        try:
            response = model.generate_content(prompt_text)
            gemini_output = response.text  # Get text content directly

            json_match = re.search(r"```json\s*(.*?)\s*```", gemini_output, re.DOTALL)
            if json_match:
                json_string = json_match.group(1)
            else:
                json_string = gemini_output  # Try to parse the whole output if markers are missing

            gemini_json = json.loads(json_string)
            logging.debug(
                f"CVE: {cve_id} - Successfully parsed JSON output from Gemini."
            )
            return gemini_json
        except json.JSONDecodeError:
            if json_retry_count < max_json_retries:
                correction_prompt = prompt_text + "\n\n"
                logging.debug(
                    "Gemini output was not valid JSON. Requesting JSON correction."
                )
                correction_prompt += "**Response was not valid JSON.**\n\n"
                correction_prompt += "Please provide your response again as a valid JSON object, and ensure it is enclosed in ```json and ``` markers.\n"
                correction_prompt += "```json\n"
                correction_prompt += "{\n"
                correction_prompt += '"malicious_intent_likely": true/false,\n'
                correction_prompt += '"reason": "brief explanation of your reasoning"\n'
                correction_prompt += "}\n"
                correction_prompt += "```\n"
                correction_prompt += (
                    "Ensure your response is enclosed in ```json and ``` markers."
                )
                response = model.generate_content(correction_prompt)
                gemini_output = response.text
                json_match = re.search(
                    r"```json\s*(.*?)\s*```", gemini_output, re.DOTALL
                )
                if json_match:
                    json_string = json_match.group(1)
                    try:
                        gemini_json = json.loads(json_string)
                        return gemini_json
                    except json.JSONDecodeError:
                        pass  # Still invalid after correction prompt, fall through to retry/fail
                json_retry_count += 1  # Increment JSON retry counter
            else:
                logging.warning(f"Max JSON decode retries reached for CVE analysis.")

            return {
                "malicious_intent_likely": False,
                "reason": f"Could not parse Gemini JSON output after correction attempts: {gemini_output}",
            }

        except google.api_core.exceptions.GoogleAPIError as e:
            if e.status_code == 429 and retry_count < max_retries:  # 429 is rate limit
                wait_time = 2**retry_count  # Exponential backoff
                logging.info(f"Rate limit hit. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
                retry_count += 1
                logging.debug(
                    f"Retrying Gemini API request, attempt {retry_count}/{max_retries}."
                )
            elif isinstance(
                e, google.api_core.exceptions.ServiceUnavailable
            ):  # Explicitly check for ServiceUnavailable
                retry_count += 1
                if retry_count <= max_retries:
                    wait_time = 5  # Fixed delay for ServiceUnavailable errors
                    logging.warning(
                        f"Service Unavailable (503) error encountered. Retrying in {wait_time} seconds... (Attempt {retry_count}/{max_retries})"
                    )
                    time.sleep(wait_time)
                else:
                    logging.error(
                        f"Max retries reached for Service Unavailable error. Aborting."
                    )
                    return {
                        "malicious_intent_likely": False,
                        "reason": f"Gemini API Service Unavailable after max retries: {e}",
                    }
            elif isinstance(
                e, google.api_core.exceptions.InternalServerError
            ):  # Explicitly check for InternalServerError
                logging.error(
                    f"Internal Server Error (500) from Gemini API. This indicates a server-side issue. No retry."
                )
                return {
                    "malicious_intent_likely": False,
                    "reason": f"Gemini API Internal Server Error: {e}",
                }  # No retry for internal server error
            elif isinstance(
                e, google.generativeai.types.generation_types.BlockedPromptException
            ):
                logging.warning(
                    f"CVE: {cve_id} - Gemini API blocked the prompt. No retry."
                )
                return {
                    "malicious_intent_likely": False,
                    "reason": f"Gemini API blocked the prompt: {e}",
                }  # No retry for blocked prompt
            elif "Invalid operation: The `response.text` quick accessor requires the response to contain a valid `Part`" in str(
                e
            ) and "finish_reason" in str(
                e
            ):
                logging.error(
                    f"CVE: {cve_id} - Gemini API returned an empty response (finish_reason 3). Inspecting safety ratings."
                )
                safety_ratings_match = re.search(
                    r"safety_ratings are: \[(.*?)\],", str(e)
                )
                safety_ratings_str = (
                    safety_ratings_match.group(1)
                    if safety_ratings_match
                    else "No safety ratings found in error message."
                )
                return {
                    "malicious_intent_likely": False,
                    "reason": f"Gemini API returned empty response due to safety filters or other issue (finish_reason 3). Safety Ratings: [{safety_ratings_str}] . Original error: {e}",
                }
            else:
                logging.error(
                    f"Gemini API error after max retries for CVE analysis: {e}"
                )
                return {
                    "malicious_intent_likely": False,
                    "reason": f"Gemini API error: {e}",
                }  # For other API errors after max retries
        except Exception as e:  # Catch any other exceptions
            logging.error(f"Unexpected error during Gemini API call: {e}")
            return {
                "malicious_intent_likely": False,
                "reason": f"Unexpected error during Gemini API call: {e}",
            }  # Broader exception catch


def process_cve(cve_id, cve_description, references, scraped_content_index):
    logging.info(f"CVE: {cve_id} - Analyzing CVE: {cve_id}")
    result = analyze_with_gemini(
        cve_id, cve_description, references, scraped_content_index
    )
    logging.info(f"CVE: {cve_id} - Analysis for CVE {cve_id}: {result}")
    return cve_id, result


STATE_FILE = Path("malicious_intent_analyzer_state.json")


def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)


if __name__ == "__main__":
    logging.debug("Starting main execution block.")
    nvd_data_dir = Path("../nvd_data")
    output_file = Path("malicious_intent_analysis_results.json")

    if not nvd_data_dir.is_dir():
        logging.error(f"Error: NVD data directory '{nvd_data_dir}' not found.")
        exit(1)
    logging.debug(f"NVD data directory found: {nvd_data_dir}")

    results = {}
    processed_cves_state = load_state()
    processed_cves_count = 0  # Counter for processed CVEs in this run
    scraped_content_index = load_index()  # Load scraped content index

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        output_file_path = Path("malicious_intent_analysis_results.json")
        futures = []
        for file_path in tqdm(
            nvd_data_dir.glob("CVE-*.json"), desc="Processing CVE files"
        ):  # Assumes filenames start with CVE-
            with open(file_path, "r") as f:
                cve_data = json.load(f)
                cve_id = cve_data.get("cve_id")
                if not cve_id:
                    logging.warning(f"CVE ID not found in {file_path}. Skipping.")
                    logging.debug(f"Skipping file: {file_path} due to missing CVE ID.")

                if cve_id in processed_cves_state:
                    logging.info(f"CVE {cve_id} already processed. Skipping.")
                    continue  # Skip already processed CVEs
                logging.debug(f"Processing CVE: {cve_id} from {file_path}")

                description = cve_data["vulnerability_details"]["description"]
                references = cve_data["references"]
                futures.append(
                    executor.submit(
                        process_cve,
                        cve_id,
                        description,
                        references,
                        scraped_content_index,
                    )
                )

        with open(output_file_path, "a") as output_file:
            for future in as_completed(
                futures
            ):  # Process results as they become available
                cve_id, result = future.result()
                results[cve_id] = result
                processed_cves_state[cve_id] = (
                    result  # Save to state immediately after processing
                )
                processed_cves_count += 1  # Increment counter
                json.dump({cve_id: result}, output_file)
                output_file.write("\n")
    logging.debug(f"Analysis results saved to: {output_file}")
    save_state(
        processed_cves_state
    )  # Save state after all are processed or in case of interrupt
    logging.info(
        f"Analysis results saved to {output_file}. Processed {processed_cves_count} new CVEs in this run."
    )
    logging.debug("Script finished execution.")
