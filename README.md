# Latch — URL Threat Analyzer

Latch is a self-hosted URL investigation tool intended to run inside an isolated analyst VM. It visits HTTP and HTTPS URLs in a fresh Playwright Firefox context and produces a report for each URL, including the captured page screenshot and the sources behind its verdict.

> **Run Latch only inside an isolated VM.** The browser visits submitted URLs. Latch binds its web service and egress proxy to loopback, but the launcher does not configure the VM or hypervisor firewall for you.

## What a report contains

- Deterministic verdict, confidence, analyst rationale, and evidence gaps
- Firefox visit status, response/redirect information, visible page text, and an actual screenshot when capture succeeds
- DNS and domain context, plus optional DNSTwist lookalike candidates checked with DNS only
- Static source-code indicators and results from configured reputation providers
- Optional AI intelligence summary when `OPENAI_API_KEY` is configured

Reports mask URL query values in the UI and exports. Configured threat providers receive the original submitted URL. AI receives collected page evidence and the screenshot when configured. Forms are not submitted, downloads are disabled, and uploaded `.txt` or `.csv` files are treated as URL lists; Latch does not execute uploaded files.

A `Clean` verdict is limited to the evidence and checks that completed at scan time. An `Unknown` verdict means the available evidence did not support a reliable conclusion.

## Requirements

- Windows 11 / Windows Server 2019 or newer, or a supported Linux/macOS environment
- Node.js 22 or newer
- Internet access during setup to install Node packages and Playwright Firefox
- Python 3 is optional; it enables the DNSTwist helper

## Start on Windows

1. Extract the ZIP. Open the `latch` folder.
2. Double-click `Run-Latch.bat`.
3. Wait for the PowerShell service window to say `Latch listening` and open <http://127.0.0.1:8787>.
4. Keep the service window open while using Latch.

The first launch creates `.env` from `.env.example`, installs dependencies, and downloads Playwright Firefox. If Python 3 is available, the launcher also installs DNSTwist in a local virtual environment. AI remains optional and off until an OpenAI key is added to the VM's `.env` file.

From Git Bash inside the `latch` folder, you can start the batch file with:

```bash
cmd.exe /c start "" "$(cygpath -w "$PWD/Run-Latch.bat")"
```

## Start on Linux or macOS

From the extracted `latch` folder:

```sh
cp .env.example .env
npm install
npx playwright install firefox
npm start
```

Open <http://127.0.0.1:8787> in the VM browser. The local DNS-pinning egress proxy listens on `127.0.0.1:9788` by default.

To enable DNSTwist on Linux/macOS, install Python 3 and run:

```sh
python3 -m venv .dnstwist-venv
.dnstwist-venv/bin/python -m pip install dnstwist
```

Restart Latch after installing it. For scans with up to 25 URLs, Latch checks up to 120 generated lookalike domains per URL with DNS lookups only. It does not visit candidate websites. Larger batches still run and skip DNSTwist.

## Optional provider and AI setup

Keep keys in the VM's `.env`; never put them in frontend code, a report, Git, or the ZIP. The example file lists these optional variables:

```dotenv
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
URLHAUS_AUTH_KEY=
OPENAI_API_KEY=
OPENAI_MODEL=gpt-4.1-mini
```

Each scan automatically queries configured VirusTotal, Google Safe Browsing, and URLhaus providers. Those providers receive the full URL, including query values. If `OPENAI_API_KEY` is set, Latch automatically sends collected page evidence and the screenshot to OpenAI for synthesis; provider/API charges may apply. AI does not replace the deterministic verdict. Restart Latch after editing `.env`.

RDAP is disabled. Review each provider's current terms, privacy policy, rate limits, and data handling before enabling it.

## Use the API from automation

Latch exposes a local JSON REST API on the same address as the UI. Start a scan from Git Bash or another process running on the VM:

```bash
curl -s -X POST http://127.0.0.1:8787/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"urls":["https://example.com/"]}'
```

The response includes a `scan.id`. Poll for progress and per-URL results:

```bash
curl -s http://127.0.0.1:8787/api/scans/SCAN_ID
```

Continue polling until `scan.status` is `complete`, then read each result in `scan.items[]`. A scan accepts 1–250 distinct URLs. The API uses the same automatic checks and policies as the UI.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/config` | Provider, AI, browser, and runtime availability |
| `GET` | `/api/scans` | Recent scans and results |
| `POST` | `/api/scans` | Start a scan; JSON body: `{"urls":["https://example.com/"]}` |
| `GET` | `/api/scans/{id}` | Poll one scan and retrieve reports |
| `DELETE` | `/api/scans/{id}` | Cancel a scan |

For n8n on the same VM, use an **HTTP Request** node: `POST` to `/api/scans`, save `scan.id`, then poll the `GET` endpoint until complete. A hosted n8n service or another computer cannot reach the VM's `127.0.0.1` address.

**MCP is not implemented yet.** An MCP adapter can be added over this API for agent clients later. The REST API currently binds to loopback and has no bearer-token authentication; do not expose it to a LAN, tunnel, or public internet. Add authentication and scoped access before enabling remote integrations.

## Isolation and data handling

Each URL is visited in a fresh Firefox browser context. The local egress proxy resolves destinations and rejects private, reserved, link-local, and metadata addresses; it allows public HTTP/HTTPS traffic on ports 80 and 443. Firefox also checks each request. These controls do not replace VM isolation or host firewall rules.

- Keep the VM isolated and deny unrelated outbound traffic at the VM/hypervisor firewall.
- Do not mount analyst home directories, browser profiles, or credentials into the VM.
- Never submit credentials to investigated pages.
- Findings, URL records, and screenshots are retained locally for 7 days by default; `RETENTION_DAYS` can be set from 1 to 30.
- Do not commit `.env`, `data/scans.json`, screenshots, or other scan evidence.

Firefox is regular browser automation, not a stealth engine. Bot challenges, access denials, and incomplete pages remain visible as evidence and cannot produce a Clean verdict by themselves.

## Development and verification

```sh
npm install
npm test
npm run smoke
```

`npm test` uses local fixtures and does not contact external targets or paid providers. `npm run smoke` requires Latch and Playwright Firefox to be running/installed; it visits `https://example.com/` and stores the report and screenshot locally.

## Sample report

Choose **Sample report** in the UI to preview the per-URL report with clearly marked fictional evidence. The standalone `sample-report.md` explains the same sample.
