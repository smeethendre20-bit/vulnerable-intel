import os
from groq import Groq
import pandas as pd
import csv
import ast
import subprocess
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=api_key)

METASPLOIT_PASSWORD = "kali"

# Function to load CSV files
def load_csv(filename):
    try:
        return pd.read_csv(filename, encoding='ISO-8859-1')
    except Exception as e:
        print(f"Error loading CSV {filename}: {e}")
        return None

# Function to print columns of the Exploit-DB CSV for verification
def check_exploitdb_columns(df_exploitdb):
    print("Exploit-DB CSV Columns:", df_exploitdb.columns)

# Function to search across Metasploit, SSTI, and Exploit-DB CSVs
def search_all_csvs(df_metasploit, df_ssti, df_exploitdb, keyword):
    # Existing search for Metasploit CSV
    result_metasploit = df_metasploit[(df_metasploit['Module'].str.contains(keyword, case=False, na=False)) |
                                      (df_metasploit['Description'].str.contains(keyword, case=False, na=False))]
    
    # Existing search for SSTI CSV
    result_ssti = df_ssti[(df_ssti['Platform'].str.contains(keyword, case=False, na=False)) |
                          (df_ssti['Category'].str.contains(keyword, case=False, na=False)) |
                          (df_ssti['Payload'].str.contains(keyword, case=False, na=False)) |
                          (df_ssti['Description'].str.contains(keyword, case=False, na=False))]

    # Existing search for Exploit-DB CSV
    df_exploitdb['SEARCH'] = df_exploitdb['SEARCH'].astype(str)
    result_exploitdb = df_exploitdb[df_exploitdb['SEARCH'].str.contains(keyword, case=False, na=False)]

    # Add code here to search your new CSV (e.g., xxs.csv)
    # Example:
    # result_xxs = df_xxs[(df_xxs['SomeColumn'].str.contains(keyword, case=False, na=False))]

    extracted_titles = []
    if not result_exploitdb.empty:
        for row in result_exploitdb['RESULTS_EXPLOIT']:
            try:
                exploits_list = ast.literal_eval(row)
                for exploit in exploits_list:
                    extracted_titles.append(exploit.get('Title', 'No Title'))
            except (ValueError, SyntaxError):
                continue

    # Return results from all CSVs, including your new one (e.g., result_xxs)
    return result_metasploit, result_ssti, extracted_titles

# Function to display search results
def display_results(results, columns=None, is_exploitdb=False, color_code=None):
    if is_exploitdb:
        if len(results) == 0:
            print("No matching results found.")
            return
        for title in results:
            print(f"Title: {title}\n")
    else:
        if results.empty:
            print("No matching results found.")
        else:
            for _, row in results[columns].iterrows():
                output = " | ".join(map(str, row.values)) + "\n"
                if color_code:
                    print(f"\033[{color_code}m{output}\033[0m")
                else:
                    print(output)

def run_searchsploit(keyword):
    try:
        result = subprocess.run(['searchsploit', keyword], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"Error running searchsploit: {e}")

# Function to query Groq API
def ask_ai_api(query):
    try:
        completion = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "You are an AI assistant helping a pentester in a chatbot api can you respond in less than 5 sentances."},
                {"role": "user", "content": query}
            ],
            temperature=0.7,
            max_tokens=1024,
        )
        ai_response = completion.choices[0].message.content
        
        print(f"\033[95m{ai_response}\033[0m")
        
        return ai_response
    except Exception as e:
        print(f"Error with Groq API: {e}")
        return None

# Unified chatbot function with AI prompt
def unified_chatbot(df_metasploit, df_ssti, df_exploitdb):
    print("\n" + "="*60)
    print("      Welcome to m8a8a8y-Bot (CLI Version)      ")
    print("="*60)
    print("Type 'exit' or 'quit' to close the program.")
    print("Type 'help' for usage instructions.")
    
    while True:
        query = input("\n\033[96m[m8a8a8y-Bot]>\033[0m ").strip()
        
        if not query:
            continue
            
        if query.lower() in ['exit', 'quit']:
            print("Exiting. Happy hunting!")
            break

        if query.lower() == 'help':
            print("\nUsage Tips:")
            print("- Enter a keyword (e.g., 'ssh', 'smb') to search local databases.")
            print("- Enter a CVE ID (e.g., 'CVE-2017-0144') for vulnerability details.")
            print("- Type 'y' when prompted to use AI for deep interpretation.")
            continue

        print("\n\033[93m[*] Querying Groq AI for interpretation...\033[0m")
        ai_prompt = f"The user searched for: '{query}'. If this corresponds to a vulnerability, explain it briefly. If it seems mistyped or vague, suggest the vulnerabilities they most likely meant. Keep it under 4 sentences."
        ai_query = ask_ai_api(ai_prompt)
        if not ai_query:
            print("\033[91m[!] AI failed to interpret the query.\033[0m")
        
        # Always perform local search regardless of AI choice unless they want to skip
        print("\n\033[94m[*] Searching local databases for: " + query + "\033[0m")
        
        # Perform search across all CSVs
        result_metasploit, result_ssti, result_exploitdb_titles = search_all_csvs(df_metasploit, df_ssti, df_exploitdb, query)
        
        # Display results from Metasploit
        print("\n\033[1mMetasploit Modules:\033[0m")
        display_results(result_metasploit, ['Module', 'Description'], color_code='32')
        
        # Display results from SSTI
        print("\n\033[1mSSTI Payloads:\033[0m")
        display_results(result_ssti, ['Category', 'Platform', 'Payload', 'Description'], color_code='34')
        
        # Display results from Exploit-DB
        print("\n\033[1mExploit-DB (Local CSV Matches):\033[0m")
        display_results(result_exploitdb_titles, is_exploitdb=True)

        # Display Searchsploit results
        print("\n\033[1mSearchsploit Live Results:\033[0m")
        run_searchsploit(query)

# Main function to load CSV files and start the chatbot
def main():
    # Load Metasploit CSV
    df_metasploit = load_csv('metasploit_data.csv')
    
    # Load SSTI CSV
    df_ssti = load_csv('ssti_payloads_full.csv')
    
    # Load Exploit-DB CSV
    df_exploitdb = load_csv('exploitdb.csv')

    # Add code here to load your new CSV (e.g., xxs.csv)
    # Example:
    # df_xxs = load_csv('xxs.csv')

    # Check if Exploit-DB was loaded and display sample data
    if df_exploitdb is not None:
        df_exploitdb['SEARCH'] = df_exploitdb['SEARCH'].astype(str)
        df_exploitdb['SEARCH'].replace('nan', '', inplace=True)
        print("First 10 entries of the 'SEARCH' column in Exploit-DB:")
        print(df_exploitdb['SEARCH'].head(10))
        print("First 5 rows of Exploit-DB CSV data:")
        print(df_exploitdb.head(5))
        check_exploitdb_columns(df_exploitdb)

    # Ensure all required datasets are handled before starting the chatbot
    if df_metasploit is None:
        df_metasploit = pd.DataFrame(columns=['Module', 'Description'])
    if df_ssti is None:
        df_ssti = pd.DataFrame(columns=['Category', 'Platform', 'Payload', 'Description'])
    if df_exploitdb is None:
        df_exploitdb = pd.DataFrame(columns=['SEARCH', 'RESULTS_EXPLOIT'])

    unified_chatbot(df_metasploit, df_ssti, df_exploitdb)

if __name__ == "__main__":
    main()
