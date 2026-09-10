# Python-Tool — OSINT/CTI Recon Aggregator

An open-source tool for automating the collection and correlation of OSINT from public sources, 

featuring AI-based integrative analysis to highlight (potential) relationships 

between the identified entities.

Current state:
Currently active development — see [DEVLOG.md](DEVLOG.md) for write-up and path chosen.

## Modules

* \[x] `crt.sh` 
* \[ ] `VirusTotal` 
* \[ ] `urlscan.io` 
* \[ ] AI correlation layer

## Installation

```bash
git clone https://github.com/riccardo0314/Python-Tool.git
cd Python-Tool
pip install -r requirements.txt
```

## Use

### Subdomain enumeration

```bash
python crtsh\_lookup.py example.com
```

Print found subdomain and save results on
`crtsh\_<domain>.json`.

## Disclaimer

This tool has been developed for legitimate OSINT research and reconnaiissance.

Use it only on authorised target.

## Licence

MIT

