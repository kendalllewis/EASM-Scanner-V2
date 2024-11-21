import argparse
import subprocess
import os
import concurrent.futures
import sqlite3
import xml.etree.ElementTree as ET

# Function to read contents of a file and print
def read_art_file():
    try:
        with open("art.txt") as f:
            print(f.read())
    except FileNotFoundError:
        print("[!] art.txt file not found.")

# List of common UDP ports for scanning
COMMON_UDP_PORTS = "53,67,68,69,123,137,161,162,500,514,520,623,1900,3391,4500,5353,5683"

# Run Masscan for TCP/UDP
def run_masscan(ip_ranges, rate, udp=False):
    rate = int(rate)
    for ip_range in ip_ranges:
        protocol = "U" if udp else "1-65535"
        output_file = f"masscan_output_{'udp' if udp else 'tcp'}_{ip_range.replace('/', '_')}.xml"
        masscan_cmd = f"masscan {ip_range} -p{protocol} --rate={rate // (10 if udp else 1)} -oX {output_file}"
        subprocess.run(masscan_cmd, shell=True)
        print(f"[+] Masscan {'UDP' if udp else 'TCP'} scan completed for {ip_range}.")

# Parse Masscan output
def parse_masscan_output(udp=False):
    hosts = {}
    protocol = "udp" if udp else "tcp"
    for file in os.listdir():
        if file.startswith(f"masscan_output_{protocol}") and file.endswith(".xml"):
            try:
                tree = ET.parse(file)
                root = tree.getroot()
                for host in root.findall("host"):
                    ip = host.find("address").attrib.get("addr", "")
                    ports = [port.attrib.get("portid", "") for port in host.findall("ports/port")]
                    if ip and ports:
                        hosts[ip] = hosts.get(ip, []) + ports
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")
    return hosts

# Run Nmap for targeted hosts with user-defined options
def run_nmap(targets, nmap_options, udp=False):
    scan_type = "-sU" if udp else "-sS"
    protocol = "udp" if udp else "tcp"
    for target in targets:
        ip, ports = target
        output_file = f"nmap_output_{ip}_{protocol}.xml"
        nmap_cmd = f"nmap {scan_type} {nmap_options} -p {ports} {ip} -oX {output_file}"
        subprocess.run(nmap_cmd, shell=True)
        print(f"[+] Nmap {'UDP' if udp else 'TCP'} scan with options '{nmap_options}' completed for {ip}.")

# Perform an indirect UDP scan using Nmap, filtering for open results on UDP ports only
def indirect_udp_scan(host, tcp_port, udp_port):
    temp_output_file = f"nmap_indirect_{host}_{udp_port}_temp.xml"
    cmd = f"nmap -p {tcp_port},U:{udp_port} -sSU {host} --host-timeout 10m --max-retries 2 -oX {temp_output_file}"
    subprocess.run(cmd, shell=True)
    try:
        tree = ET.parse(temp_output_file)
        root = tree.getroot()
        open_udp_found = False

        # Iterate over each port in the scan results
        for port in root.findall(".//port"):
            protocol = port.attrib.get("protocol", "")
            state = port.find("state").attrib.get("state", "")

            # Check only UDP ports and look for open state
            if protocol == "udp" and state == "open":
                open_udp_found = True
                service_element = port.find("service")
                service = service_element.attrib.get("name", "unknown") if service_element is not None else "unknown"
                print(f"port:{udp_port}/udp state:open service:{service}")

        # Only save the result if an open UDP port is found
        if open_udp_found:
            final_output_file = f"nmap_indirect_{host}_{udp_port}.xml"
            os.rename(temp_output_file, final_output_file)
            print(f"[+] Created {final_output_file} for host {host} on UDP port {udp_port}.")
        else:
            os.remove(temp_output_file)
            print(f"[!] No open UDP ports found for {host} on port {udp_port}; skipped file creation.")

    except ET.ParseError:
        print(f"[!] Error parsing {temp_output_file}. Skipping.")
        os.remove(temp_output_file)

# Run WhatWeb for web service analysis with enhanced performance options
def run_whatweb(targets, scan_level):
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # Use ThreadPoolExecutor to run multiple WhatWeb scans in parallel
        futures = [
            executor.submit(scan_with_whatweb, target, scan_level) for target in targets
        ]
        # Collect and log results as they complete
        for future in concurrent.futures.as_completed(futures):
            future.result()  # Print or log each result as it completes

def scan_with_whatweb(target, scan_level):
    # Set command with the scan level and target without a timeout
    whatweb_cmd = f"whatweb -a {scan_level} {target} --log-xml=whatweb_output_{target.replace('.', '_')}.xml"
    try:
        subprocess.run(whatweb_cmd, shell=True)  # No timeout specified
        print(f"[+] WhatWeb scan completed for {target}")
    except subprocess.CalledProcessError as e:
        print(f"[!] WhatWeb scan failed for {target}: {e}")

# Perform reverse DNS lookup with dig
def run_dig(ip):
    ptr_records = []
    try:
        dig_ptr_cmd = f"dig -x {ip} +short"
        ptr_results = subprocess.check_output(dig_ptr_cmd, shell=True, text=True).strip().splitlines()
        ptr_records = [record.strip('.') for record in ptr_results if record]
        print(f"[+] PTR records for {ip}: {ptr_records}")
    except subprocess.CalledProcessError as e:
        print(f"[!] dig command failed for {ip}: {e}")
    return ptr_records

# Merge all scan outputs into a single XML file
def merge_results():
    root = ET.Element("scan_results")
    for file in os.listdir():
        if file.endswith(".xml") and ("masscan" in file or "nmap" in file or "whatweb" in file):
            try:
                tree = ET.parse(file)
                root.append(tree.getroot())
            except ET.ParseError:
                print(f"[!] Failed to parse {file}. Skipping.")
    tree = ET.ElementTree(root)
    tree.write("final_scan_results.xml")
    print("[+] Final results merged into 'final_scan_results.xml'.")

# Set up command-line argument parsing
def setup_argparse():
    parser = argparse.ArgumentParser(description="Comprehensive EASM Scanner")
    parser.add_argument("--ip_range", help="IP range to scan")
    parser.add_argument("--input_file", help="File containing multiple IP ranges")
    parser.add_argument("--rate", default=1000, help="Rate of packets for masscan")
    parser.add_argument("--nmap_options", default="", help="Additional Nmap options")
    parser.add_argument("--scan_level", default=3, type=int, help="WhatWeb scan level (1-4)")
    return parser.parse_args()

# Read IP ranges from argument or file
def read_ip_ranges(args):
    if args.input_file:
        with open(args.input_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    elif args.ip_range:
        return [args.ip_range]
    else:
        print("Error: You must provide an IP range or input file with ranges.")
        exit(1)

# Database creation and population functions
def create_database():
    # Create the SQLite3 database and tables
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Create tables for hosts, ports (TCP and UDP), WhatWeb data, and certificates with 'updated_at' columns
    cursor.execute('''CREATE TABLE IF NOT EXISTS hosts (
                        id INTEGER PRIMARY KEY,
                        ip TEXT,
                        hostname TEXT,
                        os TEXT,
                        state TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')

    # Unified ports table for both TCP and UDP, differentiated by 'protocol' column
    cursor.execute('''CREATE TABLE IF NOT EXISTS ports (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER,
                        port INTEGER,
                        protocol TEXT CHECK(protocol IN ('tcp', 'udp')),
                        state TEXT,
                        service TEXT,
                        product TEXT,
                        version TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(host_id) REFERENCES hosts(id))''')

    # Whatweb table
    cursor.execute('''CREATE TABLE IF NOT EXISTS whatweb (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER,
                        url TEXT,
                        plugin TEXT,
                        version TEXT,
                        description TEXT,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(host_id) REFERENCES hosts(id))''')

    # Certificates table for SSL/TLS details
    cursor.execute('''CREATE TABLE IF NOT EXISTS certificates (
                        id INTEGER PRIMARY KEY,
                        host_id INTEGER,
                        port INTEGER,
                        issuer TEXT,
                        subject TEXT,
                        valid_from TEXT,
                        valid_until TEXT,
                        expiration_days INTEGER,
                        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(host_id) REFERENCES hosts(id))''')

    conn.commit()
    conn.close()

def create_triggers():
    # Connect to the database to create triggers
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Create triggers for automatic timestamp updates
    tables = ["hosts", "ports", "whatweb", "certificates"]
    for table in tables:
        cursor.execute(f'''
            CREATE TRIGGER IF NOT EXISTS update_{table}_timestamp
            AFTER UPDATE ON {table}
            FOR EACH ROW
            BEGIN
                UPDATE {table} SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
            END;
        ''')

        cursor.execute(f'''
            CREATE TRIGGER IF NOT EXISTS insert_{table}_timestamp
            AFTER INSERT ON {table}
            FOR EACH ROW
            BEGIN
                UPDATE {table} SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
            END;
        ''')

    conn.commit()
    conn.close()

def parse_xml_to_db(xml_file):
    # Connect to the SQLite3 database
    conn = sqlite3.connect("scan_results.db")
    cursor = conn.cursor()

    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Parse Nmap data
    for host in root.findall(".//host"):
        try:
            ip = host.find("address").attrib.get("addr")
            state = host.find("status").attrib.get("state", "unknown")
            hostname = host.find("hostnames/hostname").attrib.get("name", "unknown") if host.find("hostnames/hostname") is not None else None
            os_element = host.find("os/osmatch")
            os_name = os_element.attrib.get("name", "unknown") if os_element is not None else "unknown"

            # Insert host data
            cursor.execute("INSERT INTO hosts (ip, hostname, os, state) VALUES (?, ?, ?, ?)", (ip, hostname, os_name, state))
            host_id = cursor.lastrowid

            # Insert port data (both TCP and UDP)
            for port in host.findall(".//port"):
                port_id = int(port.attrib.get("portid", 0))
                protocol = port.attrib.get("protocol", "tcp")  # Identify protocol as 'tcp' or 'udp'
                port_state = port.find("state").attrib.get("state", "unknown")
                service = port.find("service").attrib.get("name", "unknown") if port.find("service") is not None else None
                product = port.find("service").attrib.get("product", "") if port.find("service") is not None else ""
                version = port.find("service").attrib.get("version", "") if port.find("service") is not None else ""

                # Insert port data
                cursor.execute('''INSERT INTO ports (host_id, port, protocol, state, service, product, version)
                                  VALUES (?, ?, ?, ?, ?, ?, ?)''',
                               (host_id, port_id, protocol, port_state, service, product, version))

                # Parse certificate data from the ssl-cert script output
                ssl_cert = port.find(".//script[@id='ssl-cert']")
                if ssl_cert is not None:
                    issuer = ""
                    subject = ""
                    valid_from = ""
                    valid_until = ""
                    expiration_days = None

                    for table in ssl_cert.findall("table"):
                        if table.attrib.get("key") == "issuer":
                            issuer = "; ".join(f"{elem.attrib['key']}: {elem.text}" for elem in table.findall("elem") if elem.text)
                        elif table.attrib.get("key") == "subject":
                            subject = "; ".join(f"{elem.attrib['key']}: {elem.text}" for elem in table.findall("elem") if elem.text)
                        elif table.attrib.get("key") == "validity":
                            for elem in table.findall("elem"):
                                if elem.attrib.get("key") == "notBefore":
                                    valid_from = elem.text
                                elif elem.attrib.get("key") == "notAfter":
                                    valid_until = elem.text
                                elif elem.attrib.get("key") == "days":
                                    expiration_days = int(elem.text)

                    # Insert certificate data
                    cursor.execute('''INSERT INTO certificates (host_id, port, issuer, subject, valid_from, valid_until, expiration_days)
                                      VALUES (?, ?, ?, ?, ?, ?, ?)''',
                                   (host_id, port_id, issuer, subject, valid_from, valid_until, expiration_days))

        except AttributeError:
            # Skip if required attributes are missing
            continue

    # Parse WhatWeb data
    for target in root.findall(".//target"):
        try:
            url = target.find("uri").text if target.find("uri") is not None else ""
            if not url:
                continue

            # Extract IP from the plugin named "IP"
            ip = target.find(".//plugin[name='IP']/string").text if target.find(".//plugin[name='IP']/string") is not None else ""

            # Find the corresponding host_id in the hosts table
            cursor.execute("SELECT id FROM hosts WHERE ip = ?", (ip,))
            host_row = cursor.fetchone()
            if host_row:
                host_id = host_row[0]

                # Iterate over each plugin to extract its details
                for plugin in target.findall("plugin"):
                    plugin_name = plugin.find("name").text if plugin.find("name") is not None else ""
                    plugin_version = plugin.find("version").text if plugin.find("version") is not None else ""
                    plugin_description = "; ".join([s.text for s in plugin.findall("string")]) if plugin.findall("string") else ""

                    # Insert WhatWeb data into the database
                    cursor.execute('''INSERT INTO whatweb (host_id, url, plugin, version, description)
                                      VALUES (?, ?, ?, ?, ?)''',
                                   (host_id, url, plugin_name, plugin_version, plugin_description))

        except Exception as e:
            # Handle parsing errors gracefully
            print(f"Error parsing WhatWeb data: {e}")
            continue

    # Commit changes and close the connection
    conn.commit()
    conn.close()

# Main function
def main():
    read_art_file()  # Display art.txt file contents at the start
    args = setup_argparse()
    ip_ranges = read_ip_ranges(args)

    # Step 1: Run TCP Masscan
    run_masscan(ip_ranges, args.rate)
    hosts_tcp = parse_masscan_output()
    nmap_targets_tcp = [(ip, ",".join(ports)) for ip, ports in hosts_tcp.items()]
    run_nmap(nmap_targets_tcp, args.nmap_options)

    # Step 3: Perform indirect UDP scans via TCP ports
    for host, tcp_ports in hosts_tcp.items():
        for udp_port in COMMON_UDP_PORTS.split(","):
            indirect_udp_scan(host, tcp_ports[0], udp_port)

    # Step 4: Run WhatWeb and p0f (if requested)
    # Collect PTR records instead of IP addresses for WhatWeb targets
    ptr_targets = set()
    for ip in hosts_tcp.keys():
        ptr_records = run_dig(ip)
        ptr_targets.update(ptr_records)

    if ptr_targets:
        run_whatweb(ptr_targets, args.scan_level)

    # Step 5: Merge results
    merge_results()

    print("[+] Starting database creation...")
    # Create the database and tables
    create_database()

    # Create triggers for automatic timestamp updates
    create_triggers()

    # Parse the final_scan_results.xml file and insert data into the database
    parse_xml_to_db("final_scan_results.xml")
    print("[+] Database populated successfully!")

if __name__ == "__main__":
    main()
