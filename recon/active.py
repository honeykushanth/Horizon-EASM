import nmap
from typing import Dict, Any, Optional
from core.logger import logger

class ActiveScanner:
    """
    Active Recon Engine executing controlled transport-layer port scans
    and service banner enumeration aligned with CEH Module 03/04 methodologies.
    """
    
    @classmethod
    def perform_scan(cls, target: str, scan_arguments: str = "-sV -F -T4") -> Optional[Dict[str, Any]]:
        """
        Executes an active network scan against a sanitized FQDN or IPv4 target.
        """
        try:
            logger.info(f"Initializing active network scanner wrapper layer for target: {target}")
            logger.info(f"Executing Nmap structural scan engine with parameters: '{scan_arguments}'")
            
            nm = nmap.PortScanner()
            nm.scan(hosts=target, arguments=scan_arguments)
            
            if target not in nm.all_hosts():
                logger.warn(f"Target host registry returned unresolvable or offline state: {target}")
                return None
                
            host_data = nm[target]
            scan_profile = {
                "host": target,
                "status": host_data.get("status", {}).get("state", "unknown"),
                "protocols": {}
            }
            
            for proto in host_data.all_protocols():
                scan_profile["protocols"][proto] = {}
                port_list = host_data[proto].keys()
                
                for port in port_list:
                    port_info = host_data[proto][port]
                    
                    service_name = port_info.get("name", "unknown")
                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    cpe_list = port_info.get("cpe", [])
                    
                    banner = f"{product} {version}".strip() if (product or version) else "unknown"
                    
                    scan_profile["protocols"][proto][port] = {
                        "state": port_info.get("state", "unknown"),
                        "service": service_name,
                        "banner": banner,
                        "cpe": cpe_list if isinstance(cpe_list, list) else [cpe_list] if cpe_list else []
                    }
                    
                    logger.success(
                        f"Discovered Port [{port}/{proto}] -> State: {port_info.get('state')} | "
                        f"Service: {service_name} | Banner: '{banner}'"
                    )
                    
            return scan_profile
            
        except nmap.PortScannerError as nse:
            logger.critical(f"Systemic binary execution failure within Nmap runtime engine: {str(nse)}")
            logger.critical("Verify that Nmap application binaries are properly configured inside system path variables.")
            return None
        except Exception as e:
            logger.critical(f"Unhandled active reconnaissance transport layer fault occurred: {str(e)}")
            return None
