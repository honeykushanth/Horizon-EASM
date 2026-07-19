# Horizon-EASM (External Attack Surface Management) Framework

## 📡 Overview
**Horizon-EASM** is an out-of-band and active security asset discovery engine engineered to catalog corporate digital perimeters, parse network service footprints, and programmatically map real-time threat surfaces against the official **NIST National Vulnerability Database (NVD) API v2.0**. 

Designed using modular DevOps Python patterns and clean defensive architectures, this tool takes chaotic target inputs (FQDNs or IPv4 addresses), processes them through non-attributable passive arrays, runs controlled transport-layer service enumeration sweeps, synthesizes compliant CPE 2.3 identifiers, and outputs structured structural telemetry data models.

---

## 🔬 Core Pipeline Architecture
The engine maps asset surfaces through a five-stage linear pipeline:

1. **Intake & Sanitization Core (`core/sanitizer.py`)**
   * Enforces RFC-compliant validation maps for standalone domains and traditional IPv4 blocks.
   * Leverages anchored regular expressions to prevent parameter injection attacks.
2. **Out-of-Band Passive Footprinting (`recon/passive.py`)**
   * Executes remote hostname lookups utilizing encrypted DNS-over-HTTPS (DoH) via public proxy paths.
   * Directly interfaces with REST-based RDAP nodes to map administrative registry records without establishing transport links to the target network.
3. **Active Network Service Probing (`recon/active.py`)**
   * Wraps the local system's `nmap` engine using targeted arguments (`-sV -F -T4`) to discover active Layer-4 perimeters efficiently.
   * Auto-patches environmental system execution paths programmatically for platform portability.
4. **Threat Intelligence Synthesis (`intel/nvd_analyzer.py`)**
   * Translates raw software version strings into strict 13-field **Common Platform Enumeration (CPE 2.3)** bindings.
   * Queries the official **NIST NVD REST API** using exponential backoff models with randomized timing jitter to bypass rate-limiting walls.
5. **Metric Synchronization Layer (`core/reporter.py` & `horizon.py`)**
   * Manages a unified execution lifecycle loop across multiple discovery targets.
   * Synthesizes dual-format output files: structured `report.json` for machine ingestion systems, and high-readability `report.md` for team remediation actions.

---

## 🚀 Quick Start Guide

### 📋 Prerequisites
* Python 3.10+ installed on the host operating system.
* **Nmap Security Scanner** installed locally and accessible within your terminal profile system environment variables.

### ⚙️ Installation & Setup
Clone the repository workspace layout and configure the library dependencies inside your local virtual environment layout:

```bash
# Clone the tracking repository
git clone https://github.com/honeykushanth/horizon-easm.git
cd horizon-easm

# Install standardized package constraints
pip install -r requirements.txt

# Execute analysis using a standard network target IP vector
python horizon.py -t 45.33.32.156

# Scan using a fully qualified domain target boundary
python horizon.py -t scanme.nmap.org