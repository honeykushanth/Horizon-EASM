import re
import time
import random
import requests
from typing import Dict, Any, List, Optional
from core.logger import logger

class NVDAnalyzer:

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    @classmethod
    def synthesize_cpe(cls, service_name: str, banner: str) -> str:

        # Normalize variables
        product = service_name.lower().strip()
        version = "*"
        
        # Simple extraction pattern for version tracking
        version_match = re.search(r'([\d.]+)', banner)
        if version_match:
            version = version_match.group(1)
            
        # Standardize common service mappings to match authoritative dictionary definitions
        if "msrpc" in product or "rpc" in product:
            return f"cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"
        if "http" in product or "apache" in product:
            return f"cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"
        if "ssh" in product:
            return f"cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"
            
        return f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"

    @classmethod
    def query_nvd_api(cls, cpe_string: str, retries: int = 3, backoff_factor: float = 2.0) -> List[Dict[str, Any]]:

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        params = {"cpeName": cpe_string}
        current_delay = backoff_factor

        logger.info(f"Interrogating NIST NVD API v2.0 database for: {cpe_string}")

        for attempt in range(retries):
            try:
                # Standardized connection thread execution matrix
                response = requests.get(cls.BASE_URL, headers=headers, params=params, timeout=10)
                
                if response.status_code == 403 or response.status_code == 503:
                    logger.warn(f"NIST NVD API rate limit tripped (Status {response.status_code}). Engaging retry strategy...")
                elif response.status_code == 200:
                    data = response.json()
                    return cls._parse_nvd_response(data)
                else:
                    logger.critical(f"NVD API returned unexpected processing boundary: {response.status_code}")
                    
            except requests.RequestException as e:
                logger.warn(f"Network transport anomaly encountered during NVD API lookup: {str(e)}")

            # Algorithmic calculation of exponential delay combined with random jitter vectors
            jitter = random.uniform(0.5, 1.5)
            sleep_time = (current_delay * (attempt + 1)) + jitter
            logger.info(f"Backoff applied. Pausing execution window for {sleep_time:.2f} seconds before attempt {attempt + 2}...")
            time.sleep(sleep_time)

        logger.critical(f"Exhausted API query thresholds. Dropping parsing pipeline contexts for: {cpe_string}")
        return []

    @classmethod
    def _parse_nvd_response(cls, response_data: Dict[str, Any]) -> List[Dict[str, Any]]:

        vulnerabilities = []
        cve_items = response_data.get("vulnerabilities", [])
        
        for item in cve_items:
            cve_wrapper = item.get("cve", {})
            cve_id = cve_wrapper.get("id", "UNKNOWN-CVE")
            descriptions = cve_wrapper.get("descriptions", [])
            summary = descriptions[0].get("value", "No operational metadata provided.") if descriptions else ""
            
            # Default threat values
            cvss_score = 0.0
            severity = "UNKNOWN"
            
            # Dynamic extraction matching CVSS v3.1 and v3.0 matrices
            metrics = cve_wrapper.get("metrics", {})
            v31_metrics = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
            
            if v31_metrics:
                cvss_data = v31_metrics[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNKNOWN")
            
            vulnerabilities.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "severity": severity,
                "summary": summary[:120] + "..." if len(summary) > 120 else summary
            })
            
        return vulnerabilities

    @classmethod
    def analyze_asset_profile(cls, scan_profile: Dict[str, Any]) -> Dict[str, Any]:

        threat_profile = {
            "host": scan_profile.get("host"),
            "status": scan_profile.get("status"),
            "vulnerabilities_mapped": []
        }

        protocols = scan_profile.get("protocols", {})
        for proto, ports in protocols.items():
            for port, info in ports.items():
                cpe_targets = info.get("cpe", [])
                
                # Dynamic fallback if standard Nmap discovery is unpopulated
                if not cpe_targets:
                    fallback = cls.synthesize_cpe(info.get("service"), info.get("banner"))
                    cpe_targets = [fallback]
                    
                for cpe in cpe_targets:
                    # Upgrade legacy hardware syntax formatting indicators to standard CPE 2.3
                    if cpe.startswith("cpe:/"):
                        cpe = cpe.replace("cpe:/", "cpe:2.3:")
                        
                    findings = cls.query_nvd_api(cpe)
                    for vuln in findings:
                        logger.success(
                            f"Live Exploitation Vector Found: Port [{port}/{proto}] -> "
                            f"Mapped to Identifier: {vuln['cve_id']} | Severity Level: {vuln['severity']} [CVSS: {vuln['cvss_score']}]"
                        )
                        threat_profile["vulnerabilities_mapped"].append({
                            "port": port,
                            "protocol": proto,
                            "service": info.get("service"),
                            **vuln
                        })
        return threat_profile