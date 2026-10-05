import os
import csv
import sys
import json
import urllib.request
import urllib.parse

def generate_report(csv_path, api_key):
    # Read the raw AgentIde results
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        results = list(reader)

    # Prepare the prompt for the AI to format into the THolder Standalone format
    prompt = """You are an elite Security Assessor. 
You are performing a standalone configuration review and EDR assessment based on AgentIde telemetry.
You will be given raw test results in JSON format.

You must generate a professional HTML report that strictly follows the GTCO Standalone Configuration Review format.

Requirements:
- Use the Abadi font family (or Arial as fallback).
- Include an "Introduction" and "Scope of Assessment" section.
- For each finding (especially FAILED tests), structure it exactly as:
  <h3>[Index]. [Module Name: Action] - [SEVERITY]</h3>
  (Severity should be CRITICAL or HIGH for fails, colored red. LOW for passes, colored green).
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Observation</div>
  <ul><li>[Explain what happened]</li></ul>
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Impact</div>
  <ul><li>[Explain the risk]</li></ul>
  <div style="background-color: #2E5FA2; color: white; padding: 4px 8px; font-weight: bold; margin-top: 10px;">Recommendation</div>
  <ul><li>[Remediation step]</li></ul>

Return ONLY valid HTML inside <html><body>...</body></html> tags. Do not include markdown blocks like ```html.

Raw Data:
""" + json.dumps(results, indent=2)

    # Call Gemini API
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    data = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2}
    }
    
    req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers, method='POST')
    print("[*] Prompting AI for standalone report generation...")
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            html_content = res_data['candidates'][0]['content']['parts'][0]['text']
            
            # Clean up markdown if present
            if html_content.startswith('```html'): html_content = html_content[7:]
            if html_content.endswith('```'): html_content = html_content[:-3]
            
            out_path = csv_path.replace('.csv', '_standalone.html')
            with open(out_path, 'w', encoding='utf-8') as out_f:
                out_f.write(html_content.strip())
            print(f"[+] AI Standalone Report generated: {out_path}")
    except Exception as e:
        print(f"[-] AI Generation failed: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_ai_report.py <path_to_report.csv>")
        sys.exit(1)
        
    # Securely load from .env file to prevent hardcoded secrets in source code
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                if line.strip().startswith('GEMINI_API_KEY='):
                    os.environ['GEMINI_API_KEY'] = line.strip().split('=', 1)[1].strip('"\'')
                    
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[-] Please set the GEMINI_API_KEY environment variable or add it to the .env file.")
        sys.exit(1)
        
    generate_report(sys.argv[1], api_key)
