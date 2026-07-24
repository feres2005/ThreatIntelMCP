


# ThreatIntelMCP

ThreatIntelMCP is a Python-based Threat Intelligence platform developed as a Final Year Engineering Project (PFE). It collects cybersecurity intelligence from multiple open-source sources, enriches it using AI and external intelligence providers, stores it in PostgreSQL, and exposes the data through the Model Context Protocol (MCP) for conversational AI assistants such as Claude Desktop.

---
## Project Status

🚧 Active Development

Current Version: Version 1

Completed:
- RSS Collection
- AI Analysis
- CVE Enrichment
- GitHub Security Advisories
- MITRE ATT&CK
- AlienVault OTX
- MCP Server
- Claude Desktop Integration

Planned:
- URLhaus
- Additional Threat Intelligence Sources
- Advanced Search & Filtering
## Features

- RSS threat intelligence collection
- AI-powered article analysis
- CVE enrichment from NVD
- GitHub Security Advisories integration
- MITRE ATT&CK techniques integration
- AlienVault OTX indicator enrichment
- PostgreSQL storage
- MCP server for AI assistants
- Claude Desktop integration
- Local intelligence caching
- Threat search tools

---

## Architecture

```
                    +----------------------+
                    |  Threat Sources      |
                    |----------------------|
                    | RSS Feeds            |
                    | NVD                 |
                    | GitHub Advisories   |
                    | MITRE ATT&CK        |
                    | AlienVault OTX      |
                    +----------+-----------+
                               |
                               v
                     +------------------+
                     | Data Collectors  |
                     +------------------+
                               |
                               v
                     +------------------+
                     | AI Analysis      |
                     | (Claude)         |
                     +------------------+
                               |
                               v
                     +------------------+
                     | Threat Enrichment|
                     +------------------+
                               |
                               v
                     +------------------+
                     | PostgreSQL       |
                     +------------------+
                               |
                               v
                     +------------------+
                     | MCP Server       |
                     +------------------+
                               |
                               v
                     +------------------+
                     | Claude Desktop   |
                     +------------------+
```

---

## Technologies

- Python 3.10
- PostgreSQL
- SQLAlchemy
- Anthropic Claude
- MCP Python SDK
- MITRE ATT&CK
- AlienVault OTX
- GitHub Security Advisories

---

## Current Modules

- RSS Collector
- AI Threat Analysis
- CVE Repository
- GitHub Advisory Repository
- MITRE ATT&CK Repository
- AlienVault OTX Repository
- MCP Server

---

## Project Structure

```
ThreatIntelMCP/
│
├── ai/
├── collectors/
├── database/
├── enrichment/
├── docs/
├── mcp_server/
├── main.py
├── requirements.txt
└── README.md
```

---

## Installation

Clone the repository

```bash
git clone https://github.com/feres2005/ThreatIntelMCP.git
```

Create a virtual environment

```bash
python -m venv venv
```

Activate it

Windows

```bash
venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create a `.env` file using `.envexample`.

Run the MCP server

```bash
python -m mcp_server.server
```

---

## Roadmap

- URLhaus integration
- MISP integration
- VirusTotal integration
- IOC correlation
- Threat scoring
- Advanced filtering
- Dashboard
- REST API


