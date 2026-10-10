<div align="center">

# Latch

### URL Threat Analyzer for Isolated Analyst VMs

Investigate suspicious URLs with a real Firefox visit, captured page evidence, reputation checks, domain context, static code indicators, and a clear report for every URL.

![Node.js 22+](https://img.shields.io/badge/Node.js-22%2B-43853d?logo=nodedotjs&logoColor=white)
![Browser](https://img.shields.io/badge/Browser-Firefox-FF7139?logo=firefoxbrowser&logoColor=white)
![Deployment](https://img.shields.io/badge/Deployment-Isolated%20VM-24543c)

[Quick start](#quick-start) · [Reports](#what-each-report-includes) · [API](#automation-api) · [Safety](#isolation-and-data-handling)

</div>

> **Run Latch only inside an isolated VM.** Latch opens submitted URLs in a browser. It is a defensive triage tool—not a sandbox replacement, a verdict oracle, or a stealth browser.

## At a glance

| | |
| --- | --- |
| **Purpose** | Per-URL threat triage with reviewable evidence |
| **Browser** | Playwright Firefox; a fresh browser context for each URL |
| **Inputs** | HTTP/HTTPS URLs pasted in the UI or loaded from `.txt` / `.csv` lists |
| **Reports** | Analyst rationale, source results, domain context, code indicators, and an actual visit screenshot when available |
| **Optional services** | VirusTotal, Google Safe Browsing, URLhaus, DNSTwist, and OpenAI |
| **Local address** | `http://127.0.0.1:8787` |
| **MCP** | Not implemented; use the local REST API for automation today |

## What each report includes

Each URL gets its own investigation report. Findings show their source and observation time so analysts can distinguish provider results from local rules and browser evidence.

- **Analyst rationale** — deterministic verdict, confidence, risk signals, and evidence gaps
- **Browser visit** — Firefox engine, final URL, page title, HTTP response, redirects, visible text, forms, linked hosts, and a captured screenshot when the visit succeeds
- **Domain intelligence** — hostname, registrable domain, DNS addresses, and DNSTwist lookalike candidates when available
- **Code indicators** — static indicators from collected page source; this does not execute page code
- **Reputation sources** — VirusTotal, Google Safe Browsing, and URLhaus when their keys are configured
- **AI summary** — optional synthesis of the collected evidence and screenshot when `OPENAI_API_KEY` is configured
- **Coverage gaps** — unavailable providers, blocked visits, and other missing evidence are shown explicitly

The UI and exports mask URL query values. Configured threat feeds still receive the original URL, including query values. When AI is enabled, collected page evidence and the screenshot are sent to OpenAI. Review provider terms, privacy, and rate limits before enabling external lookups.

> **A verdict is time- and evidence-limited.** `Clean` means the checks that completed found no indicators at observation time; it is not a safety guarantee. `Unknown` means the evidence is insufficient for a reliable conclusion.

## Quick start

### Windows VM

**Requirements:** Windows 11 or Windows Server 2019 or newer, Node.js 22+, and internet access for first-run dependency and Firefox installation. Python 3 is optional and enables DNSTwist.

1. Extract the ZIP and open the `latch` folder.
2. Double-click **`Run-Latch.bat`**.
3. Wait for the PowerShell window to show `Latch listening`, then open <http://127.0.0.1:8787>.
4. Keep the service window open while using Latch.

The launcher creates `.env` from `.env.example` if needed, installs Node dependencies, installs Playwright Firefox, and starts the service. When Python 3 is available, it also installs DNSTwist into a project-local virtual environment.

From Git Bash in the `latch` folder, start the launcher with:

```bash
cmd.exe /c start "" "$(cygpath -w "$PWD/Run-Latch.bat")"
```

### Linux or macOS

Install Node.js 22+ first. From the extracted `latch` folder:

```sh
cp .env.example .env
npm install
npx playwright install firefox
npm start
```

Open <http://127.0.0.1:8787> in the VM browser. Latch starts its local DNS-pinning egress proxy on `127.0.0.1:9788` by default. Do not expose either port publicly.

To enable DNSTwist on Linux or macOS, install Python 3 and run:

```sh
python3 -m venv .dnstwist-venv
.dnstwist-venv/bin/python -m pip install dnstwist
```

Restart Latch after installing DNSTwist. It checks up to 120 generated lookalike domains per URL for batches of up to 25 URLs. Candidate sites are checked with DNS only; they are not visited. Larger batches continue without DNSTwist.

## Optional provider setup

Keep keys in the VM's `.env` file. Never place provider keys in frontend code, reports, screenshots, Git, or the ZIP.

| Variable | Enables | Data sent |
| --- | --- | --- |
| `VIRUSTOTAL_API_KEY` | VirusTotal URL reputation | Full submitted URL |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Google Safe Browsing lookup | Full submitted URL |
| `URLHAUS_AUTH_KEY` | URLhaus lookup | Full submitted URL |
| `OPENAI_API_KEY` | Automatic AI intelligence summary | Collected page evidence and screenshot |
| `OPENAI_MODEL` | Optional model selection | Used with OpenAI; default is `gpt-4.1-mini` |

All providers are optional. Configured reputation lookups run automatically. AI stays off when no OpenAI key is present. Restart Latch after changing `.env`; API usage may incur provider charges. RDAP is disabled.

## Automation API

The local JSON REST API is available at the same origin as the UI. Start a scan from Git Bash or another process on the **same VM**:

```bash
curl -s -X POST http://127.0.0.1:8787/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"urls":["https://example.com/"]}'
```

The response includes `scan.id`. Poll that scan until it finishes:

```bash
curl -s http://127.0.0.1:8787/api/scans/SCAN_ID
```

Read per-URL results from `scan.items[]`. The API accepts 1–250 distinct URLs per scan and uses the same analysis policy as the UI.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/config` | Provider, AI, browser, and runtime availability |
| `GET` | `/api/scans` | List saved scans and results |
| `POST` | `/api/scans` | Start a scan with `{"urls":["https://example.com/"]}` |
| `GET` | `/api/scans/{id}` | Read progress and per-URL reports |
| `DELETE` | `/api/scans/{id}` | Cancel a scan |

### n8n

For an n8n instance running on the same VM, use an **HTTP Request** node to `POST /api/scans`, save the returned `scan.id`, then poll `GET /api/scans/{id}` until `scan.status` is `complete`. A hosted n8n instance or another computer cannot reach the VM's `127.0.0.1` address.

### MCP status

**There is no MCP server in this release.** The current integration surface is REST. An MCP adapter can be added later for agent clients; add authentication and scoped access before enabling remote integrations.

## Isolation and data handling

Latch is designed to run inside an isolated analyst VM. Its local proxy resolves destinations at connection time, rejects private, reserved, link-local, and metadata addresses, and allows public HTTP/HTTPS traffic on ports 80 and 443. Firefox also checks each request. These controls reduce exposure but do not replace VM isolation or host firewall rules.

- Keep the VM isolated; restrict outbound traffic at the VM/hypervisor firewall.
- Do not mount analyst home directories, browser profiles, or credentials into the VM.
- Never submit credentials to investigated pages. Forms are not submitted and downloads are disabled.
- Uploaded `.txt` and `.csv` files are treated as URL lists. Latch does not execute uploaded files or downloaded page content.
- The API binds to loopback and **does not have bearer-token authentication**. Do not expose the service or proxy to a LAN, SSH tunnel, or public internet.
- Reports and screenshots are stored locally for 7 days by default. Set `RETENTION_DAYS` from 1 to 30 to change retention.
- `.env`, `data/scans.json`, screenshots, and other scan evidence are excluded from the prepared source package.

Firefox is regular browser automation, not a stealth engine. Bot challenges, access denials, and incomplete pages remain visible as evidence; they cannot become a Clean verdict by themselves. See [Playwright's supported browser and OS requirements](https://playwright.dev/docs/intro).

## Development

```sh
npm install
npm test
npm run smoke
```

`npm test` uses local fixtures and does not contact external targets or paid providers. `npm run smoke` requires the service and Playwright Firefox to be installed and running; it visits `https://example.com/` and saves a local report and screenshot.

## Project layout

```text
latch/
├── index.html              # Analyst UI and in-app API / MCP guide
├── server/
│   ├── index.mjs           # Local API, scan queue, providers, egress proxy
│   ├── browser.mjs         # Firefox visit, evidence collection, screenshot
│   └── intelligence.mjs    # Domain, static-code, and optional AI analysis
├── scripts/                # DNSTwist helper and smoke check
├── tests/                  # Local fixture integration checks
├── Run-Latch.bat           # Windows launcher
├── Run-Latch.ps1           # Windows setup and service startup
├── .env.example            # Empty optional provider settings
└── sample-report.md        # Sample report notes
```

## Sample report

Choose **Sample report** in the UI to open a clearly labeled fictional per-URL report. Its evidence is illustrative; it contains no live visit or real screenshot.
