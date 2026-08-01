import re
import urllib.parse

class URLChecker:
    """Standalone utility for URL scanning"""

    def check(self, url_str: str) -> dict:
        flags = []
        try:
            parsed = urllib.parse.urlparse(url_str)
            domain = parsed.netloc.lower()
            scheme = parsed.scheme.lower()
            path = parsed.path.lower()
            
            # Check is_ip_based
            if re.match(r"^\d+\.\d+\.\d+\.\d+(:\d+)?$", domain):
                flags.append({"flag": "is_ip_based", "description": "URL uses IP address instead of domain name", "severity": 0.8})

            # Check is_shortened
            shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
            if any(s in domain for s in shorteners):
                flags.append({"flag": "is_shortened", "description": "URL uses a known shortener service", "severity": 0.5})

            # Check suspicious_tld
            suspicious_tlds = [".xyz", ".top", ".click", ".loan", ".work", ".tk", ".ml", ".ga", ".cf"]
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                flags.append({"flag": "suspicious_tld", "description": "URL uses a suspicious Top Level Domain", "severity": 0.6})

            # Check no_https
            if scheme == "http":
                flags.append({"flag": "no_https", "description": "URL uses unencrypted http:// connection", "severity": 0.3})

            # Check excessive_subdomains
            if domain.count('.') > 3:
                flags.append({"flag": "excessive_subdomains", "description": "URL has excessive subdomains", "severity": 0.5})

            # Check typosquatting
            typos = ["gooogle", "faceb00k", "amaz0n", "paytm1", "flipkart-offer", "sbi-online", "icici-secure"]
            if any(typo in domain for typo in typos):
                flags.append({"flag": "typosquatting", "description": "Domain contains misspellings of popular brands", "severity": 0.9})

            # Check suspicious_path
            suspicious_keywords = ["login", "verify", "secure", "update", "confirm", "account", "banking"]
            if any(kw in path for kw in suspicious_keywords):
                flags.append({"flag": "suspicious_path", "description": "Path contains keywords commonly used in phishing", "severity": 0.4})

            tld = ""
            if "." in domain:
                tld = domain.split(".")[-1]

            domain_info = {
                "parsed_domain": domain,
                "tld": tld,
                "scheme": scheme
            }

        except Exception as e:
            domain_info = {}
            flags.append({"flag": "malformed_url", "description": "URL could not be parsed correctly", "severity": 0.5})

        raw_score = sum(f["severity"] * 50 for f in flags)
        risk_score = min(100.0, raw_score)
        
        if risk_score >= 75:
            risk_level = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        if not flags:
            explanation = "No obvious risk indicators found in the URL."
        else:
            flag_names = [f["flag"].replace('_', ' ') for f in flags]
            flag_str = ", ".join(flag_names)
            explanation = f"This URL shows {len(flags)} risk flag(s): {flag_str}. Risk score: {risk_score:.0f}/100 ({risk_level})."

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "flags": flags,
            "domain_info": domain_info,
            "explanation": explanation
        }
