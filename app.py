import os
from flask import Flask, request, jsonify, send_from_directory
import pandas as pd
import ast
import subprocess
import re
import requests
from thefuzz import fuzz
from groq import Groq
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_url_path='', static_folder=os.path.join(BASE_DIR, 'public'))

# Configure Groq client using environment variable
api_key = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
if not api_key:
    print("WARNING: GROQ_API_KEY not found. AI features will be disabled.")
    client = None
else:
    client = Groq(api_key=api_key)


# --- Chatbot Backend Logic (adapted from chat.py) ---

def load_csv(filename):
    try:
        csv_path = os.path.join(BASE_DIR, filename)
        if not os.path.exists(csv_path) and os.path.exists(csv_path + '.gz'):
            csv_path += '.gz'
        return pd.read_csv(csv_path, encoding='ISO-8859-1')
    except Exception as e:
        print(f"Error loading CSV {filename}: {e}")
        return None

# Load datasets on startup
df_metasploit = load_csv('metasploit_data.csv')
if df_metasploit is None:
    df_metasploit = pd.DataFrame(columns=['Module', 'Description'])

df_ssti = load_csv('ssti_payloads_full.csv')
if df_ssti is None:
    df_ssti = pd.DataFrame(columns=['Category', 'Platform', 'Payload', 'Description'])

df_exploitdb = load_csv('exploitdb.csv')
if df_exploitdb is None:
    df_exploitdb = pd.DataFrame(columns=['SEARCH', 'RESULTS_EXPLOIT'])
else:
    df_exploitdb['SEARCH'] = df_exploitdb['SEARCH'].astype(str)
    df_exploitdb['SEARCH'].replace('nan', '', inplace=True)

def fuzzy_search_df(df, columns, query, threshold=60):
    if df.empty: return pd.DataFrame()
    scores = df[columns].apply(lambda row: max((fuzz.partial_ratio(query.lower(), str(val).lower()) for val in row if pd.notna(val)), default=0), axis=1)
    df_scored = df.copy()
    df_scored['score'] = scores
    return df_scored[df_scored['score'] >= threshold].sort_values(by='score', ascending=False).head(50)

def search_all_csvs(keyword):
    # Metasploit Fuzzy Search
    res_metasploit = fuzzy_search_df(df_metasploit, ['Module', 'Description'], keyword, threshold=60)
    
    # Add Metasploit GitHub URLs
    metasploit_results = []
    for _, row in res_metasploit.iterrows():
        module = row['Module']
        # Module path transformation for GitHub
        # Mapping: exploit -> exploits, payload -> payloads, etc.
        path_parts = module.split('/')
        if path_parts[0] == 'exploit': path_parts[0] = 'exploits'
        elif path_parts[0] == 'payload': path_parts[0] = 'payloads'
        elif path_parts[0] == 'encoder': path_parts[0] = 'encoders'
        elif path_parts[0] == 'nop': path_parts[0] = 'nops'
        
        fixed_path = '/'.join(path_parts)
        github_url = f"https://github.com/rapid7/metasploit-framework/blob/master/modules/{fixed_path}.rb"
        metasploit_results.append({
            "Module": row['Module'],
            "Description": row['Description'],
            "GitHubURL": github_url
        })

    # SSTI Fuzzy Search
    res_ssti = fuzzy_search_df(df_ssti, ['Platform', 'Category', 'Payload', 'Description'], keyword, threshold=60)
    ssti_results = res_ssti[['Category', 'Platform', 'Payload', 'Description']].fillna("").to_dict(orient='records')

    # Exploit-DB Fuzzy Search
    res_exploitdb = fuzzy_search_df(df_exploitdb, ['SEARCH'], keyword, threshold=60)
    exploitdb_titles = []
    if not res_exploitdb.empty:
        for row in res_exploitdb['RESULTS_EXPLOIT']:
            try:
                exploits_list = ast.literal_eval(row)
                for exploit in exploits_list:
                    title = exploit.get('Title', 'No Title')
                    if title not in exploitdb_titles:
                        exploitdb_titles.append(title)
            except (ValueError, SyntaxError):
                continue

    return metasploit_results, ssti_results, exploitdb_titles

def run_searchsploit(keyword):
    try:
        result = subprocess.run(['searchsploit', keyword], capture_output=True, text=True, timeout=10)
        
        # Parse output for actual exploit links
        lines = result.stdout.split('\n')
        exploits = []
        parsing = False
        
        for line in lines:
            if "Exploit Title" in line and "Path" in line:
                parsing = True
                continue
            if parsing and "---" in line:
                continue
            if parsing and not line.strip():
                # End of results block
                parsing = False
                continue
            
            if parsing and '|' in line:
                parts = line.split('|')
                if len(parts) >= 2:
                    title = parts[0].strip()
                    path = parts[1].strip()
                    url = f"https://www.exploit-db.com/exploits/{path.split('/')[-1].split('.')[0]}" if '/' in path and '.' in path else None
                    raw_github_url = f"https://gitlab.com/exploit-database/exploitdb/-/raw/main/{path}" if path else None
                    if url:
                        exploits.append({"Title": title, "URL": url, "RawURL": raw_github_url})
        
        return {
            "raw_output": result.stdout,
            "parsed_links": exploits
        }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"raw_output": "SearchSploit is not installed; local database search is still available.", "parsed_links": []}
    except Exception as e:
        return {"raw_output": f"SearchSploit error: {e}", "parsed_links": []}

def ask_ai_deep_search(query):
    # Strict validation
    import re
    is_cve = re.search(r'CVE-\d{4}-\d+', query, re.IGNORECASE)
    # Service + Version: looks for a word followed by something that looks like a version (e.g. 1.2, 2.4.49, v3.1)
    is_service_version = re.search(r'[a-zA-Z0-9\-_./]+\s+(?:v|V)?\d+(?:\.\d+)+', query)
    
    if not (is_cve or is_service_version):
        return {
            "error": "Invalid Input. AI Search only accepts CVE IDs (e.g., CVE-2021-44228) or Service + Version (e.g., Apache 2.4.49).",
            "valid": False
        }
        
    if client is None:
        return search_public_vulnerability_data(query)

    prompt = f"""
    As a specialized vulnerability researcher, find the most relevant Exploit-DB and GitHub links for the following: {query}
    
    Return the response as a valid JSON object with the following structure:
    {{
       "analysis": "Brief analysis of the vulnerability",
       "exploits": [
          {{"title": "Descriptive Title", "url": "Direct Link to Exploit-DB or GitHub"}},
          ...
       ]
    }}
    Only return the JSON object. No other text.
    """
    
    try:
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a vulnerability research expert returning raw JSON data."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            response_format={ "type": "json_object" }
        )
        import json
        return {
            "data": json.loads(completion.choices[0].message.content),
            "valid": True
        }
    except Exception as e:
        return {"error": f"Error with Groq AI: {str(e)}", "valid": False}

def search_public_vulnerability_data(query):
    """Use public CVE records and NVD search without a secret API key."""
    cve_match = re.search(r'CVE-\d{4}-\d+', query, re.IGNORECASE)
    try:
        if cve_match:
            response = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_match.group(0).upper()}", headers={"User-Agent": "VulnChatBot/1.0"}, timeout=12)
            if response.status_code == 404:
                return {"error": f"No public CVE record was found for {cve_match.group(0).upper()}.", "valid": False}
            response.raise_for_status()
            record = response.json()
            cve = record.get("cveMetadata", {})
            cna = record.get("containers", {}).get("cna", {})
            descriptions = cna.get("descriptions", [])
            description = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "No description provided.")
            refs = cna.get("references", [])
            links = [r.get("url") for r in refs if "Exploit" in r.get("tags", []) and r.get("url")]
            links = links or [f"https://www.cve.org/CVERecord?id={cve_match.group(0).upper()}", f"https://nvd.nist.gov/vuln/detail/{cve_match.group(0).upper()}"]
            entries = [{"title": f"{cve.get('cveId', cve_match.group(0).upper())} · CVE record", "url": link, "description": description[:1200]} for link in links[:5]]
            return {"data": {"analysis": "Record retrieved from the official CVE Program. Review its references and verify affected versions before acting.", "exploits": entries, "source": "CVE Program"}, "valid": True}

        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params={"keywordSearch": query, "resultsPerPage": 5}, headers={"User-Agent": "VulnChatBot/1.0"}, timeout=12)
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": "No matching CVE records were returned by the public NVD database. Try a CVE ID or a more specific product and version.", "valid": False}

        entries = []
        for item in vulnerabilities[:5]:
            cve = item.get("cve", {})
            descriptions = cve.get("descriptions", [])
            description = next((entry.get("value", "") for entry in descriptions if entry.get("lang") == "en"), "No description provided.")
            metrics = cve.get("metrics", {})
            cvss = next(iter(metrics.get("cvssMetricV31", [])), None) or next(iter(metrics.get("cvssMetricV30", [])), None) or next(iter(metrics.get("cvssMetricV2", [])), None)
            severity = "Severity not scored"
            if cvss:
                score = cvss.get("cvssData", {}).get("baseScore")
                rating = cvss.get("cvssData", {}).get("baseSeverity")
                if rating or score is not None:
                    severity = f"{rating or 'Score'}{f' · {score}/10' if score is not None else ''}"
            refs = cve.get("references", [])
            ref = next((r.get("url") for r in refs if "Exploit" in r.get("tags", [])), None)
            ref = ref or f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}"
            entries.append({"title": f"{cve.get('id', 'CVE')} · {severity}", "url": ref, "description": description[:1200]})

        return {"data": {"analysis": "Results are retrieved from the public NIST National Vulnerability Database (NVD). Review the source record and verify affected versions before acting.", "exploits": entries, "source": "NIST NVD"}, "valid": True}
    except requests.RequestException as exc:
        return {"error": f"The public NVD service could not be reached right now: {exc}", "valid": False}
    except (ValueError, TypeError) as exc:
        return {"error": f"Could not read the public NVD response: {exc}", "valid": False}

def ask_ai_api(query):
    if client is None:
        search_term = re.search(r"CVE-\d{4}-\d+", query, re.IGNORECASE)
        if search_term:
            result = search_public_vulnerability_data(search_term.group(0))
            if result.get("valid"):
                return result["data"]["exploits"][0]["description"]
        return "Local database matches are ready. For an exact CVE lookup, switch to AI Search; it uses public NVD data without an API key."
    try:
        completion = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are an AI assistant helping a pentester in a chatbot api can you respond in less than 5 sentances."},
                {"role": "user", "content": query}
            ],
            temperature=0.7,
            max_tokens=1024,
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"Error with Groq API: {e}"

# --- Flask Routes ---

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "ai_enabled": client is not None,
                    "datasets": {"metasploit": not df_metasploit.empty,
                                 "ssti": not df_ssti.empty,
                                 "exploitdb": not df_exploitdb.empty}})

@app.route('/api/ask_ai', methods=['POST'])
def api_ask_ai():
    data = request.get_json(silent=True) or {}
    query = data.get('query', '')
    if not query:
        return jsonify({"error": "No query provided"}), 400
    
    ai_interpretation = ask_ai_api(f"Search for vulnerabilities related to: {query}")
    return jsonify({"ai_interpretation": ai_interpretation})

@app.route('/api/ai_deep_search', methods=['POST'])
def api_ai_deep_search():
    data = request.get_json(silent=True) or {}
    query = data.get('query', '')
    if not query:
        return jsonify({"error": "No query provided"}), 400
    
    result = ask_ai_deep_search(query)
    return jsonify(result)

@app.route('/api/search', methods=['POST'])
def api_search():
    data = request.get_json(silent=True) or {}
    query = data.get('query', '')
    if not query:
        return jsonify({"error": "No query provided"}), 400

    # Search datasets
    res_metasploit, res_ssti, res_exploitdb_titles = search_all_csvs(query)
    
    # Run searchsploit
    searchsploit_output = run_searchsploit(query)
    
    # Detect if query looks like a CVE for MCP/Live Search Link
    import re
    cve_match = re.search(r'CVE-\d{4}-\d+', query, re.IGNORECASE)
    exploit_db_search_url = f"https://www.exploit-db.com/search?q={query}"
    if cve_match:
        cve_id = cve_match.group(0).upper()
        exploit_db_search_url = f"https://www.exploit-db.com/search?cve={cve_id}"
    
    ai_prompt = f"The user searched for: '{query}'. If this corresponds to a known vulnerability, explain it briefly. If the query is mistyped, vague, or mistaken, gently suggest the correct vulnerabilities they most likely meant. Keep your response under 4 sentences."
    ai_interpretation = ask_ai_api(ai_prompt)
    
    return jsonify({
        "metasploit": res_metasploit,
        "ssti": res_ssti,
        "exploitdb_titles": res_exploitdb_titles,
        "searchsploit": searchsploit_output["parsed_links"],
        "searchsploit_raw": searchsploit_output["raw_output"],
        "live_search_url": exploit_db_search_url,
        "google_search_url": f"https://www.google.com/search?q=site:exploit-db.com+{query}",
        "ai_interpretation": ai_interpretation
    })

@app.route('/api/fetch_exploit', methods=['GET'])
def fetch_exploit():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    
    # Simple validation to ensure we only fetch from approved GitLab raw URLs
    if not url.startswith("https://gitlab.com/exploit-database/exploitdb/-/raw/main/"):
        return jsonify({"error": "Invalid or unauthorized URL"}), 403
        
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            code = response.read().decode('utf-8', errors='replace')
        return jsonify({"code": code})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Ensure static folder exists
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
