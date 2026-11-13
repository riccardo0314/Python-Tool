# Python-Tool — OSINT/CTI Recon Aggregator

Open-source tool that automates OSINT (Open Source Intelligence) data
collection from public sources, enriches the target's IPs with Shodan,
then runs a two-model AI debate over the
results to surface relationships and prioritize what to investigate next.

## Status

🚧 Active development — see [DEVLOG.md](DEVLOG.md) for the history of
design decisions.

## How it works

```
target domain
     │
     ▼
 ┌────────────────────────────┐
 │ Collection modules         │  crt.sh · VirusTotal · urlscan.io
 └────────────────────────────┘
     │  target's own IPs
     ▼
 ┌────────────────────────────┐
 │ IP enrichment              │  Shodan (ports, CVEs, tags)
 └────────────────────────────┘
     │  shared schema: {tipo, valore, fonte}
     ▼
 ┌────────────────────────────┐
 │ AI debate (2 models)       │  5 rounds each, then a final report
 └────────────────────────────┘
     │
     ▼
 output/<domain>.json  +  output/<domain>_ai_report.json
```

## Modules

| Source | What it does | API key needed |
|---|---|---|
| [crt.sh](https://crt.sh) | Subdomain enumeration via Certificate Transparency logs (with automatic retry, the service is often unstable) | No |
| [VirusTotal](https://www.virustotal.com) | Domain reputation score and detection stats | Yes |
| [urlscan.io](https://urlscan.io) — search | Looks up existing scans for a domain (IPs, URLs). Each result is tagged `same_domain` true/false, so unrelated matches are not confused with the target's own infrastructure | No |
| [urlscan.io](https://urlscan.io) — submission | Actively submits a URL to be scanned in urlscan's sandbox. Opt-in only (`--submit`), `unlisted` by default | Yes |
| [Shodan](https://www.shodan.io) | Enriches the target's own IPs with open ports, known CVEs, hostnames and tags (e.g. `cdn`). Uses the free InternetDB API without a key (non-commercial use), or the host API if `SHODAN_API_KEY` is set. Passive: reads existing Shodan data, nothing is sent to the target | Optional |

Each module lives in `modules/` and exposes a `METADATA` dict describing
what it accepts, what it produces, and its known limits (rate limits,
reliability) — see `modules/crtsh.py` for the pattern.

## AI layer

After collection, two models analyze the aggregated data and debate it:

- Model 1 and model 2 alternate for 5 rounds each (10 messages), building on
  or challenging each other's hypotheses.
- Model 1 then writes the final report in Markdown: summary, key findings
  with confidence levels, caveats, and prioritized next steps.
- The prompts constrain the models to the collected data only. The output
  should be read as **leads to verify, not confirmed findings**.

The LLM client (`ai/llm_client.py`) is provider-agnostic and uses plain REST
calls, no vendor SDK. It supports two API shapes:

- `anthropic` — Anthropic Messages API
- `openai_compatible` — OpenAI-style Chat Completions, also used by OpenRouter
  and by local servers such as Ollama or LM Studio

Each model is configured independently in `.env`, so you can mix providers,
for example a hosted model against a local one. Pointing a model at a local
server keeps all collected data on your machine.

Long-term goal: fine-tune an open model on CTI/OSINT data and run it locally.

## Project structure

```
.
├── main.py              # entry point
├── modules/             # one file per OSINT source
│   ├── crtsh.py
│   ├── virustotal.py
│   ├── urlscan.py
│   └── shodan.py
├── ai/                  # AI correlation layer
│   ├── llm_client.py    # provider-agnostic LLM client
│   └── debate.py        # two-model debate + final report
├── utils/               # shared helpers
│   ├── ip_validator.py
│   └── url_defanger.py
└── output/              # JSON results (gitignored)
```

## Setup

```bash
git clone https://github.com/riccardo0314/Python-Tool.git
cd Python-Tool
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and fill in your keys:

```
VT_API_KEY=your_virustotal_api_key_here
URLSCAN_API_KEY=your_urlscan_api_key_here   # only for --submit
SHODAN_API_KEY=                              # optional, InternetDB is used if empty

MODEL_1_PROVIDER=openai_compatible
MODEL_1_NAME=your_model_name
MODEL_1_API_KEY=your_key
MODEL_1_BASE_URL=https://openrouter.ai/api/v1

MODEL_2_PROVIDER=openai_compatible
MODEL_2_NAME=your_other_model_name
MODEL_2_API_KEY=your_key
MODEL_2_BASE_URL=https://openrouter.ai/api/v1
```

For a local model (e.g. Ollama), use `openai_compatible`, set the base URL to
`http://localhost:11434/v1`, and leave the API key empty.

`.env` is gitignored and must never be committed — only `.env.example`
(placeholders only) is tracked.

## Usage

```bash
python main.py example.com
```

Runs all collection modules, then the AI debate, and prints the final report.
Raw results are saved to `output/<domain>.json` and the full debate plus
report to `output/<domain>_ai_report.json`.

To also run an active urlscan.io scan of `https://example.com`:

```bash
python main.py example.com --submit
```

This creates a new `unlisted` scan on urlscan.io (not searchable, but visible
to anyone with the link), so it only runs when you ask for it.

Individual modules can also be run on their own:

```bash
python modules/crtsh.py example.com
python modules/urlscan.py example.com
python modules/urlscan.py --submit https://example.com
python modules/shodan.py 8.8.8.8
```

## Disclaimer

This tool is intended for legitimate OSINT use (bug bounty, authorized
red teaming, security research, threat intelligence). Only use it
against targets you own or are authorized to test.

## License

MIT
