**EASMscanner v2.0 Release Notes**

**Overview**

EASMscanner v2.0 is a comprehensive and versatile External Attack Surface Scanner and Management tool designed to streamline the discovery, scanning, and analysis of network assets. This release introduces several powerful features, enhanced automation, and improved performance to meet the demands of modern security teams.

EASMscanner is built for flexibility, allowing users to conduct multi-protocol scans, analyze web services, and integrate results into centralized databases for advanced data analysis and visualization.

**Key Features**

1. Unified Multi-Protocol Scanning

- Masscan: High-speed discovery of TCP and UDP ports.
- Nmap: Granular port analysis and indirect UDP scans, focusing on open ports and service identification.
- WhatWeb: Web service fingerprinting with enhanced multi-threaded support.
- Reverse DNS Lookup: Automated DNS resolution using dig.

2. Automated Data Parsing and Enrichment

- XML parsing for both Masscan and Nmap outputs, seamlessly integrated with database storage.
- Support for SSL/TLS certificate analysis, extracting issuer, subject, validity, and expiration details.

3. Centralized SQLite Database

- Structured storage for:
   - Hosts (IP, hostname, OS, state)
   - Ports (TCP/UDP, state, service, product, version)
   - Web technologies (WhatWeb data)
   - SSL/TLS certificates
- Automatic timestamp management with triggers for updated_at fields.

4. Enhanced Reporting

- Merges all scan outputs into a single XML file for streamlined reporting.
- Dynamically creates a normalized database schema for better analysis and integration with visualization tools (e.g., Grafana).

5. Performance Improvements

- Asynchronous scanning with concurrent.futures for faster web service enumeration.
- Configurable scan rates and thread management for optimized performance on large networks.

6. Flexible Configuration

- Support for scanning individual IP ranges or batch inputs from a file.
- User-defined Masscan rates, Nmap options, and WhatWeb scan levels.
- Output files organized by scan type, protocol, and target IP for easy navigation.

**What’s New in v2.0**

- One script now handles scanning, parsing, and database creation.
- Indirect UDP Scanning: Validate UDP port states using TCP responses for improved accuracy.
- SSL/TLS Certificate Parsing: Extract certificate details directly from Nmap scans.
- Improved Web Scanning: Multi-threaded WhatWeb execution for faster web technology discovery.
- Database Enhancements: Unified port table (TCP and UDP) with support for service, product, and version data.
- Automated Merging: Consolidate results into a single XML file for comprehensive reporting.

**Usage**

EASMscanner is designed for ease of use with extensive command-line options:

python3 easmscanner.py --ip_range 192.168.0.0/24 --rate 500 --nmap_options "-A -Pn" --scan_level 3


Or, scan multiple ranges from an input file:

python3 easmscanner.py --input_file targets.txt --rate 1000
![image](https://github.com/user-attachments/assets/c3e62911-5c0c-46bd-9bc5-95b6c92aabe8)

Once your database is created, you are free to use within any reporting or dashboard tool you would like. I love the Grafana route with Docker:
![image](https://github.com/user-attachments/assets/a9f8083f-293d-42aa-96bb-3c50dd182607)


**Acknowledgments**

Special thanks to the contributors and open-source projects (Masscan, Nmap, WhatWeb, SQLite) that made this release possible.

**Suggestions or Feedback**

Let us know how EASMSCanner v2.0 performs for you! Feedback and feature requests are always welcome.
