import shodan
import socket
import whois
import requests
import json
import sys
import ipaddress
from datetime import datetime

SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"

api = shodan.Shodan(SHODAN_API_KEY)

RISKY_PORTS = {21, 22, 23, 25, 3389, 445, 3306, 5432}

# -------------------------------
# Utilities
# -------------------------------
def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def resolve_domain(domain):
    try:
        return list(set([r[4][0] for r in socket.getaddrinfo(domain, None)]))
    except socket.gaierror:
        return []


def get_domain_age(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = (datetime.utcnow() - created).days
            return age
    except Exception:
        pass
    return None


def ct_log_lookup(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return list(set(entry["name_value"] for entry in data))
    except Exception:
        pass
    return []


# -------------------------------
# Risk Scoring
# -------------------------------
def calculate_risk(data):
    score = 0

    if not data["dns_resolves"]:
        score += 20

    if data["domain_age"] is not None and data["domain_age"] < 90:
        score += 30

    if not data["cdn_protected"]:
        score += 20

    score += len(data["risky_ports"]) * 10

    return min(score, 100)


def severity(score):
    if score >= 75:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 15:
        return "LOW"
    return "CLEAN"


# -------------------------------
# IP Analysis
# -------------------------------
def analyze_ip(ip):
    result = {
        "ip": ip,
        "organization": None,
        "country": None,
        "ports": [],
        "risky_ports": [],
        "cdn_protected": False
    }

    try:
        host = api.host(ip)
        result["organization"] = host.get("org")
        result["country"] = host.get("country_name")
        result["ports"] = host.get("ports", [])

        if "cloudflare" in str(host.get("org", "")).lower():
            result["cdn_protected"] = True

        result["risky_ports"] = [p for p in result["ports"] if p in RISKY_PORTS]

    except shodan.APIError:
        pass

    return result


# -------------------------------
# Main Analyzer
# -------------------------------
def analyze_target(target):
    report = {
        "target": target,
        "timestamp": datetime.utcnow().isoformat(),
        "dns_resolves": False,
        "resolved_ips": [],
        "ct_subdomains": [],
        "domain_age": None,
        "ip_analysis": [],
        "cdn_protected": False,
        "risky_ports": [],
        "risk_score": 0,
        "severity": ""
    }

    if is_ip(target):
        ip_data = analyze_ip(target)
        report["dns_resolves"] = True
        report["resolved_ips"] = [target]
        report["ip_analysis"].append(ip_data)
        report["cdn_protected"] = ip_data["cdn_protected"]
        report["risky_ports"] = ip_data["risky_ports"]

    else:
        ips = resolve_domain(target)

        if ips:
            report["dns_resolves"] = True
            report["resolved_ips"] = ips

            for ip in ips:
                ip_data = analyze_ip(ip)
                report["ip_analysis"].append(ip_data)
                report["cdn_protected"] |= ip_data["cdn_protected"]
                report["risky_ports"].extend(ip_data["risky_ports"])

        else:
            # Domain does not resolve
            report["ct_subdomains"] = ct_log_lookup(target)

        report["domain_age"] = get_domain_age(target)

    report["risk_score"] = calculate_risk(report)
    report["severity"] = severity(report["risk_score"])

    return report


# -------------------------------
# CLI
# -------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python shodan_passive_intel.py <IP_or_DOMAIN>")
        sys.exit(1)

    target = sys.argv[1]
    analysis = analyze_target(target)

    output_file = f"intel_{target.replace('.', '_')}.json"
    with open(output_file, "w") as f:
        json.dump(analysis, f, indent=4)

    print(f"[+] Analysis completed")
    print(f"[+] Severity: {analysis['severity']} ({analysis['risk_score']}/100)")
    print(f"[+] Report saved to {output_file}")
