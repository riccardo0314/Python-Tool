# Devlog

Notes on my decisions during the development, cronological order.

## 2026-09 — Setup 

* Goal: build an OSINT tool to aggregate publicly available sources 

&#x09;and using an AI model to correlate found entities and highlight patterns 

* First module: `crtsh\_lookup.py`, subdomain enumeration via
Certificate Transparency logs. No API key needed: easiest way to go.
* Choosen common data format for every modules:
`{"type": ..., "value": ..., "source": ...}` — so that every source
"speaks the same language" and in future phases, comparison will be easier.
* Storage: JSON for now. A graph could be a valid idea for the future,

&#x09;only if entity relationships become effectively complex to explore with a plain JSON.

