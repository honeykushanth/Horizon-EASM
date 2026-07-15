import time
import random
import requests
from typing import Dict, Any, List, Optional
from core.logger import logger

class NVDAnalyzer:

    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @classmethod
    def synthesize_cpe(cls, service_name: str, banner: str) -> Optional[str]:

        try:
            product = service_name.lower().strip()
            if not product or product == "unknown":
                return None
            
            # Extract basic version tracking points out of standard banners
            version = "any"
            banner_words = banner.lower().split()
            for word in banner_words:
                # Basic heuristic looking for digit blocks (e.g., 8.4p1, 2.4.41)
                if any(char.isdigit() for char in word) and not word.startswith("cpe"):
                    version = word.strip("',()[]")
                    break

            # Synthesize into standardized CPE 2.3 application scheme format
            synthesized = f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"
            return synthesized
        except Exception as e:
            logger.critical(f"Failed parsing version strings for CPE fallback: {str(e)}")
            return None

    @classmethod
    def fetch_cves(cls, cpe_string: str, max_retries: int = 3) -> List[Dict[str, Any]]:

        vulnerabilities = []
        params = {"cpeName": cpe_string}
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Horizon-EASM/1.0"}
        
        # Strip trailing legacy wildcards if accidentally carried over from Nmap
        if cpe_string.endswith(":*"):
            params["cpeName"] = cpe_string[:-2]

        delay = 2.0  # Initial base delay factor for network rate limits
        
        for attempt in range(max_retries):
            try:
                response = requests.get(cls.BASE_URL, params=params, headers=headers, timeout=10)
                
                # Check for strict NIST rate-limiting firewall constraints (HTTP 403 / 503)
                if response.status_code in [403, 503, 429]:
                    jitter = random.uniform(0.5, 1.5)
                    sleep_time = (delay * (2 ** attempt)) + jitter
                    logger.warn(f"NIST NVD Rate Limit Hit (Status: {response.status_code}). Backing off for {sleep_time:.2f}s...")
                    time.sleep(sleep_time)
                    continue
                    
                response.raise_for_status()
                data = response.json()
                
                # Unpack complex nested JSON vulnerability matrices from NIST schema
                vulnerabilities_list = data.get("vulnerabilities", [])
                for item in vulnerabilities_list:
                    cve_data = item.get("cve", {})
                    cve_id = cve_data.get("id")
                    
                    # Parse CVSS Metrics (Prioritize v3.1, fallback to legacy v2.0 profiles)
                    metrics = cve_data.get("metrics", {})
                    cvss_score = 0.0
                    severity = "UNKNOWN"
                    
                    if "cvssMetricV31" in metrics:
                        v31_info = metrics["cvssMetricV31"][0].get("cvssData", {})
                        cvss_score = v31_info.get("baseScore", 0.0)
                        severity = v31_info.get("baseSeverity", "UNKNOWN")
                    elif "cvssMetricV2" in metrics:
                        v2_info = metrics["cvssMetricV2"][0].get("cvssData", {})
                        cvss_score = v2_info.get("baseScore", 0.0)
                        severity = metrics["cvssMetricV2"][0].get("baseSeverity", "UNKNOWN")

                    vulnerabilities.append({
                        "cve_id": cve_id,
                        "cvss": cvss_score,
                        "severity": severity
                    })
                
                return vulnerabilities

            except requests.RequestException as e:
                if attempt == max_retries - 1:
                    logger.critical(f"Network transport fault during NVD intelligence collection: {str(e)}")
                time.sleep(delay)
                
        return vulnerabilities