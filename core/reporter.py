import json
import os
from datetime import datetime
from typing import Dict, Any
from core.logger import logger

class HorizonReporter:

    @classmethod
    def write_json_report(cls, data: Dict[str, Any], output_path: str = "report.json") -> bool:
        """Writes structural asset intelligence maps out to flat JSON matrices."""
        try:
            logger.info(f"Compiling automation metrics into JSON schema: {output_path}")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            logger.success(f"JSON data matrix synchronized successfully: {output_path}")
            return True
        except Exception as e:
            logger.critical(f"Failed to generate JSON asset profile log: {str(e)}")
            return False

    @classmethod
    def write_markdown_report(cls, data: Dict[str, Any], output_path: str = "report.md") -> bool:
        """Synthesizes threat inventory records into structural Markdown blueprints."""
        try:
            logger.info(f"Compiling corporate remediation layout into Markdown: {output_path}")
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            md = []
            md.append("# 🚀 HORIZON-EASM EXTERNAL SURFACING SCAN BRIEF")
            md.append(f"**Execution Timestamp:** `{timestamp}` | **Target Profile:** `{data.get('target', 'Unknown')}`")
            md.append("\n---")
            
            # Passive Intelligence Mapping
            md.append("\n## 📡 1. OUT-OF-BAND OSINT METRICS")
            passive = data.get("passive_recon", {})
            dns_records = passive.get("dns", {})
            md.append(f"- **Discovered A Records:** {', '.join(dns_records.get('A', [])) if dns_records.get('A') else 'None'}")
            
            rdap = passive.get("rdap", {})
            md.append("- **Authoritative Domain Registry Handle:** " + f"`{rdap.get('handle', 'N/A')}`")
            
            # Active Transport & Vulnerability Profiles
            md.append("\n## 🔬 2. ACTIVE RECONNAISSANCE & THREAT SURFACE MATRIX")
            active = data.get("active_recon", {})
            protocols = active.get("protocols", {})
            
            if not protocols:
                md.append("*No open layer-4 communication perimeters enumerated.*")
            else:
                for proto, ports in protocols.items():
                    md.append(f"\n### Transport Layer Protocol: `{proto.upper()}`")
                    md.append("| Port | State | Service | Application Banner | Mapped Risk Profiles |")
                    md.append("| :--- | :--- | :--- | :--- | :--- |")
                    for port, info in ports.items():
                        cves = data.get("vulnerabilities", {}).get(str(port), [])
                        cve_links = [f"[{v['cve_id']}](https://nvd.nist.gov/vuln/detail/{v['cve_id']}) (CVSS: {v['cvss']})" for v in cves]
                        cve_str = "<br>".join(cve_links) if cve_links else "✅ Clean (0 Mapped)"
                        
                        md.append(f"| `{port}` | {info.get('state')} | {info.get('service')} | `{info.get('banner')}` | {cve_str} |")

            with open(output_path, "w", encoding="utf-8") as f:
                f.write("\n".join(md))
            
            logger.success(f"Actionable Markdown brief written cleanly: {output_path}")
            return True
        except Exception as e:
            logger.critical(f"Failed to write corporate report summary structure: {str(e)}")
            return False