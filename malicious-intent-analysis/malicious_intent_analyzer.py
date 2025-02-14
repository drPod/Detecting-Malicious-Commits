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
    prompt_text = f"""
    Analyze the following CVE description and associated references to determine if the vulnerability
    was likely introduced with malicious intent."""
    prompt_text += """

    """
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
                correction_prompt = prompt_text + """

**Response was not valid JSON.**

Please provide your response again as a valid JSON object, and ensure it is enclosed in ```json and ``` markers.
```json
{
"malicious_intent_likely": true/false,
"reason": "brief explanation of your reasoning"
}
```
Ensure your response is enclosed in ```json and ``` markers."""
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
