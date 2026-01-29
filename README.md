# Intelligence Analyzer Using Shodan(Free tier)
A **passive intelligence gathering tool** that uses the Shodan free API, DNS resolution, WHOIS, and Certificate Transparency (CT) logs to analyze IP addresses or domains and produce a risk-scored JSON report.

⚠️ This tool performs passive analysis only.
No scanning, exploitation, or active probing is performed.

---
## ✨ Features
- 🔍 IP & Domain analysis
- 🌐 DNS resolution (domain → IP)
- 🧾 Certificate Transparency (CT) log checks when domains don’t resolve
- 📅 Domain age detection (WHOIS)
- 🚪 Exposed services & risky ports (Shodan)
- 🛡️ CDN detection (basic heuristic)
- 📊 Risk scoring & severity classification
- 📁 JSON report export
- 💻 Command-line interface

---
## 🧠 What This Tool Is (and Is Not)
✅ What it does
- Uses public & passive data sources
- Works with Shodan free tier
- Helps analysts prioritize risk
- Designed for OSINT / CTI / SOC learning
❌ What it does NOT do
- No vulnerability exploitation
- No port scanning
- No confirmation of malicious activity
- No guarantee of complete Shodan data (free tier limitation)

---
## 📦 Requirements
- Python 3.8+
- Shodan API Key(Free Tier)
- Standard libraries used `socket`, `json`, `sys`, `ipaddress`, `datetime`.
  ```bash
  pip install shodan python-whois requests
  ```

---
## 🔑 Shodan API Key Setup(API Configuration)
Create a .env file in the project directory:
```bash
SHODAN_API_KEY="YOUR_SHODAN_API_KEY"
```

---
## 🚀 Usage
### Analyze an IP address
```bash
python shodan_passive_intel.py 8.8.8.8
```
### Analyze a domain
```bash
python shodan_passive_intel.py example.com
```

---
## 📄 Output
- A JSON file is generated automatically:
  ```bash
  intel_example_com.json
  intel_8_8_8_8.json
  ```
- Console Output example
  ```bash
  [+] Analysis completed
  [+] Severity: CLEAN (0/100)
  [+] Report saved to intel_example_com.json
  ```

---
## 🧾 JSON Report Structure
```json
{
    "target": "example.com",
    "timestamp": "2026-01-29T07:30:12.000Z",
    "dns_resolves": true,
    "resolved_ips": [
        "104.18.26.120"
    ],
    "ct_subdomains": [],
    "domain_age": null,
    "ip_analysis": [
        {
            "ip": "104.18.26.120",
            "organization": "Cloudflare, Inc.",
            "country": "United States",
            "ports": [],
            "risky_ports": [],
            "cdn_protected": true
        }
    ],
    "cdn_protected": true,
    "risky_ports": [],
    "risk_score": 0,
    "severity": "CLEAN"
}
```

---
## 📊 Risk Scoring Logic (Simplified)
| Condition	               | Score Impact|
|:---:                     | :---:       |
| Domain does not resolve	 |  +20        |
| Domain age < 90 days	   |  +30        |
| Not CDN-protected	       |  +20        |
| Each risky port exposed	 |  +10        |
| Max score	               |  100        |

### Severity Levels
- CLEAN (0–14)
- LOW (15–39)
- MEDIUM (40–74)
- HIGH (75–100)
⚠️ Severity ≠ confirmed malicious activity

---
## 🚪 Risky Ports Tracked
```text
21   FTP
22   SSH
23   Telnet
25   SMTP
445  SMB
3389 RDP
3306 MySQL
5432 PostgreSQL
```

---
## 🔐 CDN Detection
Basic heuristic:
Checks organization string for known CDN names (e.g., Cloudflare)
⚠️ CDN detection is best-effort, not guaranteed.

---
## 🧪 Certificate Transparency (CT) Logs
If a domain **does not resolve via DNS**, the tool:
- Queries **crt.sh**
- Extracts historical subdomains from TLS certificates
This helps identify:
- Dormant infrastructure
- Historical exposure
- Typosquatted or abandoned assets

---
## ⚠️ Important Limitations
* Shodan free API does not return:
  - Full port lists consistently
  - Historical banners
  - Complete geolocation data
* WHOIS data may be:
  - Redacted
  - Inconsistent
  - Missing creation dates
* CT logs **do not imply active services**

---
## 🎯 Intended Use Cases
- OSINT & Threat Intelligence learning
- SOC analyst enrichment workflows
- Bug bounty reconnaissance (passive)
- CTI report enrichment
- Interview / portfolio demonstration

---
## 📌 Disclaimer
> This tool provides passive intelligence only.
> All findings are indicative, not authoritative.
> Do not treat risk scores as proof of compromise.
Use responsibly and ethically.

---
## 🤝 Contributions
Feel free to:
- Improve risk scoring
- Add MITRE ATT&CK mapping
- Add alternative data sources (Censys, GreyNoise, etc.)
- Improve CDN detection
