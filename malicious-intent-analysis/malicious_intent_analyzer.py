import json
import google.generativeai as genai

# Configure Gemini API - replace with your actual API key or setup
genai.configure(
    api_key="YOUR_GEMINI_API_KEY"
)  # Consider loading API key from environment variable
model = genai.GenerativeModel("gemini-pro")


def analyze_with_gemini(cve_description: str, references: list):
    """
    Analyzes CVE description and references using Gemini to determine malicious intent.
    """
    prompt_text = f"""                                                                                                                                                                                                                      
    Analyze the following CVE description and associated references to determine if the vulnerability                                                                                                                                       
    was likely introduced with malicious intent.                                                                                                                                                                                            
                                                                                                                                                                                                                                            
    CVE Description:                                                                                                                                                                                                                        
    {cve_description}                                                                                                                                                                                                                       
                                                                                                                                                                                                                                            
    References:                                                                                                                                                                                                                             
    """
    for ref in references:
        tags_str = ", ".join(ref.get("tags", []))
        prompt_text += f"- URL: {ref.get('url', 'N/A')}, Tags: [{tags_str}]\n"

    prompt_text += """                                                                                                                                                                                                                      
    Based on the description and references, is it likely that this vulnerability was introduced with malicious intent?                                                                                                                     
    Consider factors such as:                                                                                                                                                                                                               
    - Keywords in the description suggesting intentional backdoor, sabotage, or malicious code.                                                                                                                                             
    - References pointing to exploit code, discussions of malicious use, or indicators of compromise.                                                                                                                                       
    - Tags like 'exploit', 'malware', 'backdoor' in the references.                                                                                                                                                                         
                                                                                                                                                                                                                                            
    Respond with a JSON object in the following format:                                                                                                                                                                                     
    {{                                                                                                                                                                                                                                      
    "malicious_intent_likely": true/false,                                                                                                                                                                                                
    "reason": "brief explanation of your reasoning"                                                                                                                                                                                       
    }}                                                                                                                                                                                                                                      
    """

    try:
        response = model.generate_content(prompt_text)
        gemini_output = response.text  # Or response.parts if you need structured data
        # --- Parse Gemini Output ---
        try:
            gemini_json = json.loads(gemini_output)
            return gemini_json
        except json.JSONDecodeError:
            return {
                "malicious_intent_likely": False,
                "reason": f"Could not parse Gemini JSON output: {gemini_output}",
            }

    except Exception as e:
        return {"malicious_intent_likely": False, "reason": f"Gemini API error: {e}"}
