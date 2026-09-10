# Python-Tool for CTI



The evolution of my Python skills. This repository is a collection of my Python scripts/tools, specifically focused on Cybersec and CTI daily tasks.

## Tools Included

### 1. URL Defanger (`url_defanger.py`)
A quick, light and easy script to neutralize malicious URLs before sharing them with  team or in reports. It prevents accidental clicks by replacing protocols and wrapping dots.

### 2. IP Validator (`ip_validator.py`)
A script that takes an IP address as input and mathematically verifies if it's a valid IPv4/IPv6 address, discarding malformed data.

---
*These tools mark the beginning of my Python journey (Day 3!). The goal is to continuously update them and add more complex automations as my skills grow.*

---
### 3. # Python-Tool — OSINT/CTI Recon Aggregator

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

## Subdomain enumeration

```bash
python crtsh\_lookup.py example.com
```

Print found subdomain and save results on
`crtsh\_<domain>.json`.


---

## Disclaimer

These tools have been developed for legitimate OSINT research and reconnaiissance.

Use them only on authorised target.

## Licence

MIT


