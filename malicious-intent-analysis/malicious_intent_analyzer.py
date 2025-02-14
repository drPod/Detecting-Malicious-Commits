import json
import google.generativeai as genai
import os
from dotenv import load_dotenv
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load environment variables from .env file
load_dotenv()

# Configure Gemini API - replace with your actual API key or setup
genai.configure(
    api_key=os.getenv("GEMINI_API_KEY")
)
model = genai.GenerativeModel("gemini-pro")


def analyze_with_gemini(cve_description: str, references: list):
    """
    Analyzes CVE description and references using Gemini to determine malicious intent.
    """
    prompt_text = "Analyze the following CVE description and associated references to determine if the vulnerability "
    prompt_text += "was likely introduced with malicious intent.\n\n"
    prompt_text += "CVE Description: " + cve_description + "\n\n"
    prompt_text += "References:\n"
    for ref in references:
        tags_str = ", ".join(ref.get("tags", []))
        prompt_text += "- URL: " + ref.get('url', 'N/A') + ", Tags: [" + tags_str + "]\n"

    prompt_text += """Based on the description and references, is it likely that this vulnerability was introduced with malicious intent?
Consider factors such as:
- Keywords in the description suggesting intentional backdoor, sabotage, or malicious code.
- References pointing to exploit code, discussions of malicious use, or indicators of compromise.
- Tags like 'exploit', 'malware', 'backdoor' in the references.

Respond with a JSON object in the following format:
```json
{
"malicious_intent_likely": true/false,
"reason": "brief explanation of your reasoning"
}
```
Ensure your response is enclosed in ```json and ``` markers."""

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
                json_string = gemini_output # Try to parse the whole output if markers are missing

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
                correction_prompt += "Ensure your response is enclosed in ```json and ``` markers."
                response = model.generate_content(correction_prompt)
                gemini_output = response.text
                json_match = re.search(r"```json\s*(.*?)\s*```", gemini_output, re.DOTALL)
                if json_match:
                    json_string = json_match.group(1)
                    try:
                        gemini_json = json.loads(json_string)
                        return gemini_json
                    except json.JSONDecodeError:
                        pass # Still invalid after correction prompt, fall through to retry/fail

            return {"malicious_intent_likely": False, "reason": f"Could not parse Gemini JSON output even after correction: {gemini_output}"}

        except genai.APIError as e: # Catch API errors, including rate limits
            if e.status_code == 429 and retry_count < max_retries: # 429 is rate limit
                wait_time = 2 ** retry_count # Exponential backoff
                print(f"Rate limit hit. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)
                retry_count += 1
            else:
                return {"malicious_intent_likely": False, "reason": f"Gemini API error: {e}"} # Propagate other API errors or max retries reached
        except Exception as e: # Catch any other exceptions
            return {"malicious_intent_likely": False, "reason": f"Gemini API error: {e}"} # Broader exception catch
def process_cve(cve_id, cve_description, references):
    print(f"Analyzing CVE: {cve_id}") # Optional: for logging/monitoring
    result = analyze_with_gemini(cve_description, references)
    print(f"Analysis for CVE {cve_id}: {result}") # Optional: for logging/monitoring
    return cve_id, result

if __name__ == "__main__":
    # Example Usage (replace with your actual CVE data loading logic)
    cve_data_list = [
        {"cve_id": "CVE-TEST-001", "description": "Test CVE description 1.", "references": [{"url": "http://example.com", "tags": ["test"]}]},
        {"cve_id": "CVE-TEST-002", "description": "Test CVE description 2.", "references": [{"url": "http://example2.com", "tags": ["test2"]}]},
        # ... more CVE data
    ]

    with ThreadPoolExecutor(max_workers=10) as executor: # Adjust max_workers as needed
        futures = [executor.submit(process_cve, cve_data['cve_id'], cve_data['description'], cve_data['references']) for cve_data in cve_data_list]
        results = {}
        for future in as_completed(futures):
            cve_id, result = future.result()
            results[cve_id] = result

    print("All analyses completed.")
    print("Results:", results) # Or process/save the results as needed
