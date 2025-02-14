import json
from pathlib import Path
import google.generativeai as genai
import os
from dotenv import load_dotenv
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# Define max workers in a variable
MAX_WORKERS = 10

# Load environment variables from .env file
load_dotenv()

# Setup logging
logging.basicConfig(filename='malicious_intent_analyzer.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configure Gemini API - replace with your actual API key or setup
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-pro")


def analyze_with_gemini(cve_description: str, references: list):
    """
    Analyzes CVE description and references using Gemini to determine malicious intent.
    """
    prompt_text = "Analyze the following CVE description and associated references to determine if the vulnerability was likely introduced with malicious intent. "
    prompt_text += "\n\n"
    prompt_text += "CVE Description: " + cve_description + ". "
    prompt_text += "\n\n"
    prompt_text += "References: " + "\n"
    for ref in references:
        tags_str = ", ".join(ref.get("tags", []))
        prompt_text += (
            "- URL: " + ref.get("url", "N/A") + ", Tags: [" + tags_str + "]\n"
        )

    prompt_text += "Based on the description and references, is it likely that this vulnerability was introduced with malicious intent? "
    prompt_text += """Consider factors such as:
- Keywords in the description suggesting intentional backdoor, sabotage, or malicious code.
- References pointing to exploit code, discussions of malicious use, or indicators of compromise.
- Tags like 'exploit', 'malware', 'backdoor' in the references.
"""
    prompt_text += "Respond with a JSON object in the following format:\n"
    prompt_text += "```json\n"
    prompt_text += "{\n"
    prompt_text += '"malicious_intent_likely": true/false,\n'
    prompt_text += '"reason": "brief explanation of your reasoning"\n'
    prompt_text += "}\n"
    prompt_text += "```\n"
    prompt_text += "Ensure your response is enclosed in ```json and ``` markers."

    retry_count = 0
    max_retries = 3
    while retry_count <= max_retries:
        try:
            response = model.generate_content(prompt_text)
            gemini_output = response.text

            json_match = re.search(r"```json\s*(.*?)\s*```", gemini_output, re.DOTALL)
            if json_match:
                json_string = json_match.group(1)
            else:
                json_string = gemini_output  # Try to parse the whole output if markers are missing

            gemini_json = json.loads(json_string)
            return gemini_json
        except json.JSONDecodeError:
            if retry_count < max_retries:
                correction_prompt = prompt_text + "\n\n"
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

            return {
                "malicious_intent_likely": False,
                "reason": f"Could not parse Gemini JSON output even after correction: {gemini_output}",
            }

        except genai.APIError as e:  # Catch API errors, including rate limits
            if e.status_code == 429 and retry_count < max_retries:  # 429 is rate limit
                wait_time = 2**retry_count  # Exponential backoff
                logging.info(f"Rate limit hit. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
                retry_count += 1
            else:
                return {
                    "malicious_intent_likely": False,
                    "reason": f"Gemini API error: {e}",
                }  # Propagate other API errors or max retries reached
        except Exception as e:  # Catch any other exceptions
            return {
                "malicious_intent_likely": False,
                "reason": f"Gemini API error: {e}",
            }  # Broader exception catch


def process_cve(cve_id, cve_description, references):
    logging.info(f"Analyzing CVE: {cve_id}")
    result = analyze_with_gemini(cve_description, references)
    logging.info(f"Analysis for CVE {cve_id}: {result}")
    return cve_id, result


STATE_FILE = Path("malicious_intent_analyzer_state.json")

def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=4)


if __name__ == "__main__":
    nvd_data_dir = Path("../nvd_data")
    output_file = Path("malicious_intent_analysis_results.json")

    if not nvd_data_dir.is_dir():
        logging.error(f"Error: NVD data directory '{nvd_data_dir}' not found.")
        exit(1)

    results = {}
    processed_cves_state = load_state()
    processed_cves_count = 0  # Counter for processed CVEs in this run

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for file_path in tqdm(nvd_data_dir.glob("CVE-*.json"), desc="Processing CVE files"):  # Assumes filenames start with CVE-
            with open(file_path, "r") as f:
                cve_data = json.load(f)
                cve_id = cve_data.get("cve_id")  # Use .get() to avoid KeyError
                if not cve_id:
                    logging.warning(f"CVE ID not found in {file_path}. Skipping.")
                    continue  # Skip to the next file

                if cve_id in processed_cves_state:
                    logging.info(f"CVE {cve_id} already processed. Skipping.")
                    continue  # Skip already processed CVEs

                description = cve_data["vulnerability_details"]["description"]
                references = cve_data["references"]
                futures.append(
                    executor.submit(process_cve, cve_id, description, references)
                )

        for future in as_completed(futures):  # Process results as they become available
            cve_id, result = future.result()
            results[cve_id] = result
            processed_cves_state[cve_id] = result  # Save to state immediately after processing
            processed_cves_count += 1  # Increment counter

    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    save_state(processed_cves_state)  # Save state after all are processed or in case of interrupt
    logging.info(f"Analysis results saved to {output_file}. Processed {processed_cves_count} new CVEs in this run.")
