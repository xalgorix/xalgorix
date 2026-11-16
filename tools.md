# Xalgorix Tools

Complete list of **70+ security tools** included in Xalgorix - the most powerful open-source AI autonomous pentesting agent.

## 🔍 Recon & Subdomain Enumeration (15 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **subfinder** | Passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| 2 | **findomain** | Subdomain discovery | `cargo install findomain` |
| 3 | **assetfinder** | Find related subdomains | `go install github.com/tomnomnom/assetfinder@latest` |
| 4 | **dnsx** | DNS resolution & bruteforce | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| 5 | **amass** | Subdomain enumeration | `go install github.com/owasp-amass/amass/v4/...@latest` |
| 6 | **gospider** | Web spidering | `go install github.com/jaeles-project/gospider@latest` |
| 7 | **katana** | Next-gen crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| 8 | **hakrawler** | Web crawling | `go install github.com/hakluke/hakrawler@latest` |
| 9 | **gau** | Get All URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| 10 | **waybackurls** | Wayback Machine URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| 11 | **paramspider** | Parameter discovery | `pipx install git+https://github.com/devanshbatham/paramspider.git` |
| 12 | **crt.sh** | Certificate transparency | `curl -s "https://crt.sh/?q=target.com"` |
| 13 | **bufferover** | DNS enumeration | `curl -s "https://dns.bufferover.run/dns?q=target.com"` |
| 14 | **webarchive** | Historical URLs | `curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*"` |
| 15 | **shuffledns** | DNS bruteforce | `go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` |

## 🌐 HTTP & Scanning (15 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **httpx** | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| 2 | **nuclei** | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| 3 | **gobuster** | Directory busting | `go install github.com/OJ/gobuster/v3@latest` |
| 4 | **ffuf** | Fuzzing | `go install github.com/ffuf/ffuf/v2@latest` |
| 5 | **feroxbuster** | Recursive fuzzing | `cargo install feroxbuster --locked` |
| 6 | **dirsearch** | Web path scanning | `git clone https://github.com/maurosoria/dirsearch` |
| 7 | **dirb** | Web scanning | `apt install dirb` |
| 8 | **nikto** | Web server scanning | `apt install nikto` |
| 9 | **wfuzz** | Web fuzzing | `pip install wfuzz` |
| 10 | **whatweb** | Web technology fingerprint | `apt install whatweb` |
| 11 | **wappalyzer** | Technology stack detection | `npm install -g wappalyzer` |
| 12 | **builtwith** | Technology lookup | `pip install builtwith` |
| 13 | **wpscan** | WordPress scanner | `gem install wpscan` |
| 14 | **joomscan** | Joomla scanner | `git clone https://github.com/rezasp/joomscan` |
| 15 | **cmsmap** | CMS scanner | `git clone https://github.com/Dionach/CMSmap` |

## 💉 Exploitation (15 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **sqlmap** | SQL injection | `git clone https://github.com/sqlmapproject/sqlmap` |
| 2 | **nmap** | Port & service scanning | `apt install nmap` |
| 3 | **masscan** | Fast port scanner | `apt install masscan` |
| 4 | **naabu** | Fast port scanner | `go install github.com/projectdiscovery/naabu/cmd/naabu@latest` |
| 5 | **arp-scan** | ARP discovery | `apt install arp-scan` |
| 6 | **netdiscover** | Network discovery | `apt install netdiscover` |
| 7 | **responder** | LLMNR/NBTNS spoofing | `git clone https://github.com/SpiderLabs/Responder` |
| 8 | **impacket** | Windows exploitation | `pip install impacket` |
| 9 | **secretdump** | SAM database dump | `pip install impacket` |
| 10 | **evilwinrm** | Windows remoting | `gem install evil-winrm` |
| 11 | **hydra** | Password cracking | `apt install hydra` |
| 12 | **medusa** | Password cracking | `apt install medusa` |
| 13 | **john** | Password cracking | `apt install john` |
| 14 | **hashcat** | GPU password cracking | `apt install hashcat` |
| 15 | **crackmapexec** | Network exploitation | `apt install crackmapexec` |

## 🕵️ Information Gathering (10 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **theHarvester** | Email gathering | `git clone https://github.com/laramies/theHarvester` |
| 2 | **metagoofil** | Metadata extraction | `apt install metagoofil` |
| 3 | **spiderfoot** | OSINT automation | `apt install spiderfoot` |
| 4 | **recon-ng** | Web reconnaissance | `apt install recon-ng` |
| 5 | **maltego** | Graphical OSINT | `apt install maltego` |
| 6 | **gh** | GitHub reconnaissance | `apt install gh` |
| 7 | **git-dumper** | Git repository dump | `pip install git-dumper` |
| 8 | **gittools** | Git exploitation | `git clone https://github.com/internetwache/GitTools` |
| 9 | **trufflehog** | Secret scanning | `go install github.com/trufflesecurity/trufflehog@latest` |
| 10 | **gitleaks** | Secret detection | `go install github.com/gitleaks/gitleaks@latest` |

## 🔐 Security Scanning (10 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **zaproxy** | Web app scanner | `apt install zaproxy` |
| 2 | **burpsuite** | Web vulnerability | `apt install burpsuite` |
| 3 | **semgrep** | Static analysis | `pip install semgrep` |
| 4 | **bandit** | Python security | `pip install bandit` |
| 5 | **brakeman** | Ruby on Rails security | `gem install brakeman` |
| 6 | **gosec** | Go security | `go install github.com/securego/gosec@latest` |
| 7 | **sonarqube** | Code quality | `docker run -d --name sonarqube -p 9000:9000 sonarqube` |
| 8 | **owasp-zap** | App security | `apt install zaproxy` |
| 9 | **mitmproxy** | HTTP proxy | `apt install mitmproxy` |
| 10 | **sslyze** | TLS analysis | `pip install sslyze` |

## 🛡️ WAF & Protection (4 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **wafw00f** | WAF detection | `pip install wafw00f` |
| 2 | **whatwaf** | WAF identification | `git clone https://github.com/Ekultek/WhatWaf` |
| 3 | **subjack** | Subdomain takeover | `go install github.com/haccer/subjack@latest` |
| 4 | **nuclei-templates** | Vuln templates | `git clone https://github.com/projectdiscovery/nuclei-templates` |

## 🔧 Utilities (15 tools)

| # | Tool | Purpose | Install |
|---|------|---------|---------|
| 1 | **curl** | HTTP client | Built-in |
| 2 | **wget** | Downloader | Built-in |
| 3 | **jq** | JSON processing | `apt install jq` |
| 4 | **git** | Version control | Built-in |
| 5 | **python3** | Scripting | Built-in |
| 6 | **pip** | Package manager | Built-in |
| 7 | **scrapling** | Anti-bot bypass | `pipx install scrapling` |
| 8 | **xurl** | URL manipulation | `go install github.com/lestrrat-go/xurl@latest` |
| 9 | **qsreplace** | Query string | `go install github.com/tomnomnom/qsreplace@latest` |
| 10 | **unfurl** | URL parsing | `go install github.com/tomnomnom/unfurl@latest` |
| 11 | **anew** | Add new lines | `go install github.com/tomnomnom/anew@latest` |
| 12 | **gron** | JSON parsing | `go install github.com/tomnomnom/gron@latest` |
| 13 | **httprobe** | HTTP probe | `go install github.com/tomnomnom/httprobe@latest` |
| 14 | **httpx** | HTTP toolkit | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| 15 | **notify** | Webhook notifications | `go install github.com/projectdiscovery/notify/cmd/notify@latest` |

## 🤖 Agent Tools (Built-in)

| Tool | Description |
|------|-------------|
| **terminal_execute** | Run shell commands with auto-install |
| **browser** | Browser automation |
| **playwright** | Browser control for testing |
| **websearch** | Web search via Gemini/Brave/Google/Bing |
| **notes** | Track findings and endpoints |
| **reporting** | Generate PDF reports |
| **thinking** | AI reasoning and planning |
| **finish** | Complete and summarize scan |

## Auto-Install Feature

Xalgorix **automatically installs** any missing tools when needed! Just run a command and it'll handle the installation.

### Supported Package Managers
- **Go** - `go install`
- **APT** - `apt install`
- **PIP** - `pip install`
- **Cargo** - `cargo install`
- **Gem** - `gem install`
- **NPM** - `npm install`

## Summary

| Category | Count |
|----------|-------|
| Recon & Subdomain | 15 |
| HTTP & Scanning | 15 |
| Exploitation | 15 |
| Information Gathering | 10 |
| Security Scanning | 10 |
| WAF & Protection | 4 |
| Utilities | 15 |
| **TOTAL** | **85+** |

Xalgorix supports **85+ security tools** for comprehensive penetration testing!
