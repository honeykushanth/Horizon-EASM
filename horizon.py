import argparse
import sys
from core.logger import logger
from core.sanitizer import TargetSanitizer
from recon.passive import PassiveScanner
from recon.active import ActiveScanner
from intel.nvd_analyzer import NVDAnalyzer
from core.reporter import HorizonReporter

def pad_cpe_23(cpe_str: str) -> str:

    # Normalize legacy Nmap prefix cpe:/ to cpe:2.3:
    if cpe_str.startswith("cpe:/"):
        cpe_str = cpe_str.replace("cpe:/", "cpe:2.3:")
    
    fields = cpe_str.split(":")
    
    # If it is formatted as a legacy prefix without explicit version fields
    if len(fields) < 13:
        needed = 13 - len(fields)
        cpe_str += ":*" * needed
        
    return cpe_str

def main():
    parser = argparse.ArgumentParser(
        description="Horizon-EASM: Production-Grade External Attack Surface Management Framework.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="Sanitized Target FQDN or IPv4 infrastructure address.")
    parser.add_argument("--skip-active", action="store_true", help="Execute out-of-band passive intelligence modules exclusively.")
    args = parser.parse_args()

    logger.info("==========================================================")
    logger.info("   HORIZON-EASM : ASSET RECONNAISSANCE & THREAT MAPPING   ")
    logger.info("==========================================================")

    # Phase 1: In-Scope Domain/IP Intake Boundary
    clean_target, target_type = TargetSanitizer.clean_target(args.target)
    if not clean_target or target_type == "INVALID":
        logger.critical(f"Aborting execution layout. Input scope is illegal or structural anomaly: {args.target}")
        sys.exit(1)

    # Master Data Accumulator Schema
    master_manifest = {
        "target": clean_target,
        "type": target_type,
        "passive_recon": {"dns": {}, "rdap": {}},
        "active_recon": {},
        "vulnerabilities": {}
    }

    # Phase 2: Passive Footprinting Engine (OOB OSINT)
    logger.info(f"Launching Phase 2 Passive Tracking Layer against: {clean_target}")
    dns_a_records = PassiveScanner.query_dns(clean_target, "A")
    master_manifest["passive_recon"]["dns"]["A"] = dns_a_records if dns_a_records else []
    
    rdap_metadata = PassiveScanner.query_rdap(clean_target, target_type)
    master_manifest["passive_recon"]["rdap"] = rdap_metadata if rdap_metadata else {}

    # Phase 3 & 4: Active Footprinting & Threat Vulnerability Processing
    if args.skip_active:
        logger.warn("Skipping active perimeter layer scanning as explicit execution parameter flag.")
    else:
        logger.info(f"Initializing Phase 3 Active Network Wrapper Layer against: {clean_target}")
        scan_results = ActiveScanner.perform_scan(clean_target)
        
        if scan_results:
            master_manifest["active_recon"] = scan_results
            logger.info("Advancing to Phase 4 Threat Processing Matrix...")
            
            protocols = scan_results.get("protocols", {})
            for proto, ports in protocols.items():
                for port, info in ports.items():
                    cpe_list = info.get("cpe", [])
                    banner = info.get("banner", "")
                    service_name = info.get("service", "unknown")
                    
                    cpe_23 = None
                    # Evaluate structural CPE presence
                    if cpe_list and len(cpe_list) > 0:
                        # Normalize and pad the native Nmap discoverable CPE
                        cpe_23 = pad_cpe_23(cpe_list[0])
                    else:
                        # Call fallback synthesis algorithm engineered in Phase 4
                        synthesized = NVDAnalyzer.synthesize_cpe(service_name, banner)
                        if synthesized:
                            cpe_23 = pad_cpe_23(synthesized)
                    
                    if cpe_23:
                        logger.info(f"Interrogating NIST NVD database for Port [{port}/{proto}] -> {cpe_23}")
                        vulns = NVDAnalyzer.fetch_cves(cpe_23)
                        if vulns:
                            master_manifest["vulnerabilities"][str(port)] = vulns
                            logger.success(f"Successfully mapped {len(vulns)} threat vector fields for Port [{port}/{proto}]")
        else:
            logger.critical("Active discovery modules returned dead tracking metrics or offline state.")

    # Phase 5: Reporting Synthesis Channel
    logger.info("Initializing Phase 5 Reporting and Metric Synchronization...")
    HorizonReporter.write_json_report(master_manifest, "report.json")
    HorizonReporter.write_markdown_report(master_manifest, "report.md")

    logger.success("==========================================================")
    logger.success("🚀 END-TO-END OPERATIONAL SCAN BLOCKS SYNCED & LOCKED DOWN")
    logger.success("==========================================================")

if __name__ == "__main__":
    main()