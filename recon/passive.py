import requests
from typing import Dict, Any, Optional
from core.logger import logger

class PassiveScanner:
    
    DOH_URL = "https://cloudflare-dns.com/dns-query"
    
    # Resilient multi-tier gateway topology for high-reliability lookups
    RDAP_GATEWAYS = [
        "https://rdap.iana.org/domain/",
        "https://rdap.org/domain/"
    ]
    RDAP_IP_URL = "https://rdap.arin.net/registry/ip/"

    REQ_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
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
        Gathers out-of-band WHOIS context using a fault-tolerant RDAP gateway matrix.
        """
        if target_type == "IPv4":
            return cls._execute_rdap_request(f"{cls.RDAP_IP_URL}{target}", target)
        
        # Iterates through gateways if a transport drop or 403 occurs
        for gateway in cls.RDAP_GATEWAYS:
            lookup_url = f"{gateway}{target}"
            logger.info(f"Interrogating public RDAP registry via [{gateway}]: {target}")
            result = cls._execute_rdap_request(lookup_url, target)
            if result and "error" not in result:
                return result
                
        logger.critical(f"All public RDAP gateways failed to parse asset metadata for {target}")
        return None

    @classmethod
    def _execute_rdap_request(cls, url: str, target: str) -> Optional[Dict[str, Any]]:
        """Core network transport handler for RDAP querying."""
        try:
            response = requests.get(url, headers=cls.REQ_HEADERS, timeout=10)
            
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
            elif response.status_code == 404:
                logger.warn(f"Asset record not found in this registry endpoint: {target}")
                return {"status": "NOT_FOUND", "error": True}
            else:
                logger.warn(f"Registry endpoint returned non-200 state [{response.status_code}] for target: {target}")
                return {"error": True}
        except (requests.RequestException, Exception) as e:
            logger.warn(f"Transport layer failure on endpoint link: {str(e)}")
            return {"error": True}