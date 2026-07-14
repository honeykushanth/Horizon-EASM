import requests
from typing import Dict, Any, Optional
from core.logger import logger

class PassiveScanner:
    
    DOH_URL = "https://cloudflare-dns.com/dns-query"
    # Utilizing explicit regional root fallbacks to maximize availability
    RDAP_DOMAIN_URL = "https://rdap.verisign.com/com/v1/domain/"
    RDAP_IP_URL = "https://rdap.arin.net/registry/ip/"

    # Production-grade User-Agent string to prevent 403 programmatic blocking triggers
    REQ_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "application/json"
    }

    @classmethod
    def query_dns(cls, target: str, record_type: str = "A") -> Optional[list]:
        """
        Queries Cloudflare DoH API for a clean, out-of-band DNS resolution matrix.
        """
        try:
            headers = {**cls.REQ_HEADERS, "Accept": "application/dns-json"}
            params = {"name": target, "type": record_type}
            
            logger.info(f"Retrieving passive DNS [{record_type}] records for: {target}")
            response = requests.get(cls.DOH_URL, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if "Answer" in data:
                    records = [ans["data"] for ans in data["Answer"]]
                    logger.success(f"Discovered {len(records)} [{record_type}] records for {target}")
                    return records
                logger.warn(f"No [{record_type}] records returned for target scope: {target}")
                return []
            else:
                logger.critical(f"DoH API returned unexpected downstream state: {response.status_code}")
                return None
        except requests.RequestException as e:
            logger.critical(f"Network transport fault during DoH enumeration: {str(e)}")
            return None
        except Exception as e:
            logger.critical(f"Unhandled exception in passive DNS parser: {str(e)}")
            return None

    @classmethod
    def query_rdap(cls, target: str, target_type: str) -> Optional[Dict[str, Any]]:
        """
        Gathers out-of-band WHOIS context using the Registration Data Access Protocol (RDAP).
        """
        try:
            base_url = cls.RDAP_IP_URL if target_type == "IPv4" else cls.RDAP_DOMAIN_URL
            lookup_url = f"{base_url}{target}"
            
            logger.info(f"Interrogating public RDAP registry for asset profiles: {target}")
            response = requests.get(lookup_url, headers=cls.REQ_HEADERS, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                parsed_intel = {
                    "handle": data.get("handle", "N/A"),
                    "entities": [],
                    "events": []
                }
                
                if "entities" in data:
                    parsed_intel["entities"] = [
                        ent.get("handle", "UNKNOWN") for ent in data["entities"]
                    ]
                
                if "events" in data:
                    parsed_intel["events"] = [
                        f"{evt.get('eventAction', 'Action')}: {evt.get('eventDate', 'Date')}"
                        for evt in data["events"]
                    ]
                
                logger.success(f"Successfully compiled out-of-band asset metadata for {target}")
                return parsed_intel
            elif response.status_code in [403, 429]:
                logger.critical(f"Upstream registry blocked execution request via status code: {response.status_code}")
                return None
            elif response.status_code == 404:
                logger.warn(f"Asset context target records not found in public RDAP registers: {target}")
                return {"status": "NOT_FOUND"}
            else:
                logger.critical(f"RDAP infrastructure returned unexpected state: {response.status_code}")
                return None
        except requests.RequestException as e:
            logger.critical(f"Network transport fault during RDAP registration audit: {str(e)}")
            return None
        except Exception as e:
            logger.critical(f"Unhandled exception in passive registration parser: {str(e)}")
            return None