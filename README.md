# VulnChatBot

A browser based vulnerability intelligence chatbot with local Metasploit and SSTI dataset search, no-key public CVE lookups through NIST NVD, optional Groq AI explanations, and optional SearchSploit integration.

## Run locally

Requires Python 3.10 or later.

1. Install the dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

2. (Optional) Enable AI features by copying `.env.example` to `.env` and adding your Groq key:

   ```env
   GROQ_API_KEY=your_groq_api_key
   ```

   The local database search, NIST CVE lookups, and web interface work without a key. Groq enables generative explanations; the public NIST NVD database provides CVE and product-version search as the no-key alternative. SearchSploit is also optional; install it separately if you want its local exploit index.

3. Start the app from this folder:

   ```powershell
   python app.py
   ```

4. Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

Try **apache**, **ssh**, or **windows** to see included Metasploit matches. The health endpoint at `/api/health` reports which datasets and optional AI features are active.

## Docker

```sh
docker compose up --build
```

Then open [http://localhost:5000](http://localhost:5000). Add a `.env` file to the project root if you want AI features in the container.

## Included data and optional integrations

- `metasploit_data.csv` — included Metasploit module index
- `ssti_payloads_full.csv` — included SSTI payload list
- `exploitdb.csv` — optional dataset; it is not included, so Exploit-DB dataset matches are skipped
- Groq — optional AI explanation and deep search, enabled by `GROQ_API_KEY`
- SearchSploit — optional command-line integration

## Deployment

The project is configured for Vercel's Flask runtime. Connect the repository to Vercel for an automatic deployment. Keep any optional Groq key in the hosting provider's environment settings; do not commit it.

## License

MIT. See [LICENSE](LICENSE).

