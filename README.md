# Python-Tool — OSINT/CTI Recon Aggregator

Open-source tool that automates OSINT (Open Source Intelligence) data
collection from public sources, with a planned AI layer to correlate
findings and highlight relationships between entities.

## Status

🚧 Active development — see [DEVLOG.md](DEVLOG.md) for the full history
of design decisions.

## Modules

| Source | What it does | API key needed |
|---|---|---|
| [crt.sh](https://crt.sh) | Subdomain enumeration via Certificate Transparency logs | No |
| [VirusTotal](https://www.virustotal.com) | Domain reputation score and detection stats | Yes |
| [urlscan.io](https://urlscan.io) | Looks up existing scans for a domain (IPs, pages) | No |

Each module lives in `modules/` and exposes a `METADATA` dict describing
what it accepts, what it produces, and its known limits (rate limits,
reliability) — see `modules/crtsh.py` for the pattern.

Planned next: AI correlation layer to connect findings across sources.

## Project structure

```
.
├── main.py              # entry point, runs all modules on a target domain
├── modules/              # one file per OSINT source
│   ├── crtsh.py
│   ├── virustotal.py
│   └── urlscan.py
├── utils/                 # shared helpers (not tied to a specific source)
│   ├── ip_validator.py
│   └── url_defanger.py
└── output/                # JSON results (gitignored)
```

## Setup

```bash
git clone https://github.com/riccardo0314/Python-Tool.git
cd Python-Tool
pip install -r requirements.txt
```

VirusTotal requires a free API key:

1. Create an account at [virustotal.com](https://www.virustotal.com) and
   grab your API key from your profile.
2. Copy `.env.example` to `.env`.
3. Paste your key into `.env`:
   ```
   VT_API_KEY=your_key_here
   ```

`.env` is gitignored and never committed — only `.env.example` (with a
placeholder) is tracked.

## Usage

```bash
python main.py example.com
```

Runs all modules against the target domain, prints a summary, and saves
the combined results to `output/<domain>.json`.

## Disclaimer

This tool is intended for legitimate OSINT use (bug bounty, authorized
red teaming, security research, threat intelligence). Only use it
against targets you own or are authorized to test.

## License

MIT
