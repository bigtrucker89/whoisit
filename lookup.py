#!/usr/bin/python
import socket
import ipwhois
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import argparse
import time
import json
import logging
from ipaddress import ip_network, ip_address, AddressValueError
from tqdm import tqdm
from datetime import datetime
import sqlite3
import subprocess

# Database file for caching
DB_FILE = 'lookup_cache.db'

# Set up logging
logging.basicConfig(filename='lookup.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def initialize_db():
    # Create the database and table if not exists
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cache (
            ip TEXT PRIMARY KEY,
            hostname TEXT,
            ip_owner TEXT,
            whois_response TEXT,
            timestamp DATETIME
        )
    ''')
    conn.commit()
    conn.close()

def get_cache_entry(ip, max_age):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT hostname, ip_owner, whois_response, timestamp 
            FROM cache 
            WHERE ip = ? AND timestamp >= datetime('now', ?)
        ''', (ip, f'-{max_age} hours'))
        result = cursor.fetchone()
        conn.close()
        if result and result[0] and result[1]:
            logging.debug(f"Cache hit for IP: {ip} -> Hostname: {result[0]}, IP Owner: {result[1]}")
            return {'hostname': result[0], 'ip_owner': result[1], 'whois_response': result[2], 'timestamp': result[3]}
        logging.warning(f"Cache entry for IP {ip} is incomplete or expired.")
        return None
    except Exception as e:
        logging.error(f"Error retrieving cache entry for IP {ip}: {e}")
        return None

def update_cache(ip, hostname, ip_owner, whois_response):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO cache (ip, hostname, ip_owner, whois_response, timestamp)
        VALUES (?, ?, ?, ?, datetime('now'))
    ''', (ip, hostname, ip_owner, whois_response))
    conn.commit()
    conn.close()

def fallback_whois(ip):
    try:
        result = subprocess.run(["whois", ip], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            output = result.stdout
            # Extract organization or owner information from WHOIS output
            owner = "Unknown"
            for line in output.splitlines():
                if "OrgName" in line or "netname" in line or "Organization" in line:
                    owner = line.split(":")[1].strip()
                    logging.info(f"Fallback WHOIS success for IP: {ip}. Owner: {owner}")
            return owner, output
        logging.error(f"Fallback WHOIS failed for IP: {ip}. Output: {result.stdout}")
        return "WHOIS fallback lookup failed", result.stdout
    except subprocess.TimeoutExpired:
        logging.error(f"Fallback WHOIS timeout for IP: {ip}")
        return "WHOIS fallback timeout", ""
    except Exception as e:
        logging.error(f"Fallback WHOIS error for IP: {ip}. Error: {e}")
        return "WHOIS fallback error", ""

def lookup_ip(ip, throttle_delay=1, max_cache_age=24, ignore_cache=False, max_retries=3, retry_delay=5):
    try:
        # Validate IP format explicitly
        try:
            ip = ip_address(ip)
        except AddressValueError:
            logging.warning(f"Invalid IP address format detected: {ip}")
            return ip, "Invalid IP", "Invalid IP", "Error"

        if not ignore_cache:
            # Check cache first
            cache_entry = get_cache_entry(str(ip), max_cache_age)
            if cache_entry:
                logging.info(f"Cache hit for IP: {ip}. Hostname: {cache_entry['hostname']}, IP Owner: {cache_entry['ip_owner']}")
                return str(ip), cache_entry['hostname'], cache_entry['ip_owner'], "Cached"

        # Perform hostname lookup
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
        except socket.herror:
            hostname = "Hostname lookup failed"
            logging.error(f"Hostname lookup failed for IP: {ip}")

        # Perform WHOIS lookup on IP using ipwhois for block ownership
        try:
            ip_whois = ipwhois.IPWhois(str(ip))
            retries = 0
        while retries <= max_retries:
            try:
                ip_whois = ipwhois.IPWhois(str(ip))
                ip_whois_result = ip_whois.lookup_rdap()  # Retrieve RDAP data
                ip_owner = ip_whois_result.get('network', {}).get('name', 'Unknown')
                whois_response = json.dumps(ip_whois_result, indent=4)
                break  # Success, exit retry loop
            except ipwhois.exceptions.WhoisRateLimitError as e:
                retries += 1
                logging.warning(f"WHOIS rate limit error for IP: {ip}. Retry {retries}/{max_retries}. Waiting {retry_delay} seconds.")
                time.sleep(retry_delay * retries)  # Exponential backoff
                continue
            except ipwhois.exceptions.HTTPLookupError as e:
                logging.error(f"IP WHOIS HTTP Error for IP: {ip}. Error: {e}")
                ip_owner, whois_response = fallback_whois(str(ip))
                break
            except Exception as e:
                logging.error(f"General WHOIS lookup failure for IP: {ip}. Error: {e}")
                ip_owner, whois_response = fallback_whois(str(ip))
                break
            ip_owner = ip_whois_result.get('network', {}).get('name', 'Unknown')
            whois_response = json.dumps(ip_whois_result, indent=4)
        except ipwhois.exceptions.HTTPLookupError as e:
            logging.error(f"IP WHOIS HTTP Error for IP: {ip}. Error: {e}")
            ip_owner, whois_response = fallback_whois(str(ip))
        except ipwhois.exceptions.WhoisRateLimitError as e:
            logging.error(f"WHOIS rate limit error for IP: {ip}. Error: {e}")
            ip_owner, whois_response = fallback_whois(str(ip))
        except Exception as e:
            logging.error(f"General WHOIS lookup failure for IP: {ip}. Error: {e}")
            ip_owner, whois_response = fallback_whois(str(ip))

        # Add throttling to avoid excessive WHOIS lookups
        time.sleep(throttle_delay)

        # Log the new lookup
        logging.info(f"Network lookup for IP: {ip}. Hostname: {hostname}, IP Owner: {ip_owner}")

        # Update the cache
        update_cache(str(ip), hostname, ip_owner, whois_response)

        return str(ip), hostname, ip_owner, "New"
    except Exception as e:
        logging.error(f"Error during lookup for IP {ip}: {e}")
        return ip, "Error", "Error", "Error"

def perform_lookup(input_file, output_file, max_workers=None, throttle_delay=1, output_format='csv', filter_private=False, max_cache_age=24, ignore_cache=False):
    if max_workers is None:
        max_workers = os.cpu_count() * 2  # Set default to 2 threads per CPU core
    print(f"Using {max_workers} threads for processing.")
    print(f"Throttling WHOIS lookups with a {throttle_delay}-second delay.")

    initialize_db()

    try:
        with open(input_file, 'r') as infile:
            ips = []
            for line in infile:
                try:
                    ip = ip_address(line.strip())
                    if filter_private and (ip.is_private or ip.is_reserved):
                        logging.info(f"Skipping private/reserved IP: {ip}")
                        continue
                    ips.append(str(ip))
                except AddressValueError:
                    logging.warning(f"Invalid IP address format: {line.strip()}")
                    continue  # Skip invalid IPs

            print(f"Total IPs to process: {len(ips)}")
            results = []
            summary = {"cached": 0, "new": 0, "errors": 0}

            # Use ThreadPoolExecutor to perform lookups concurrently
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ip = {executor.submit(lookup_ip, ip, throttle_delay, max_cache_age, ignore_cache): ip for ip in ips}

                for future in tqdm(as_completed(future_to_ip), total=len(ips), desc="Processing IPs"):
                    try:
                        ip, hostname, ip_owner, source = future.result()
                        results.append({"ip": ip, "hostname": hostname, "ip_owner": ip_owner, "source": source})
                        if source == "Cached":
                            summary["cached"] += 1
                        elif source == "New":
                            summary["new"] += 1
                        logging.info(f"Processed: {ip} -> Hostname: {hostname}, IP Owner: {ip_owner}, Source: {source}")
                    except Exception as e:
                        summary["errors"] += 1
                        logging.error(f"Error processing IP: {future_to_ip[future]}. Error: {e}")

        # Write results to output file in the specified format
        with open(output_file, 'w') as outfile:
            if output_format == 'csv':
                outfile.write("IP Address, Hostname, IP Owner, Source\n")
                for result in results:
                    outfile.write(f"{result['ip']}, {result['hostname']}, {result['ip_owner']}, {result['source']}\n")
            elif output_format == 'json':
                json.dump(results, outfile, indent=4)

        # Print summary of results
        print("Summary:")
        print(f"  Cached: {summary['cached']}")
        print(f"  New Lookups: {summary['new']}")
        print(f"  Errors: {summary['errors']}")

    except FileNotFoundError:
        logging.error(f"Input file '{input_file}' not found.")
        print(f"Input file '{input_file}' not found.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Perform hostname and WHOIS lookups on IP addresses.")
    parser.add_argument("input_file", help="Path to the input file containing IP addresses.")
    parser.add_argument("output_file", help="Path to the output file to store the results.")
    parser.add_argument("--threads", type=int, default=None, help="Number of threads to use (default: 2x CPU cores).")
    parser.add_argument("--throttle", type=float, default=1, help="Throttle delay (in seconds) between WHOIS lookups to avoid rate limits.")
    parser.add_argument("--format", choices=['csv', 'json'], default='csv', help="Output format: 'csv' or 'json' (default: csv).")
    parser.add_argument("--filter-private", action='store_true', help="Filter out private and reserved IP addresses.")
    parser.add_argument("--max-cache-age", type=int, default=24, help="Maximum cache age in hours (default: 24 hours).")
    parser.add_argument("--ignore-cache", action='store_true', help="Ignore cache and perform all lookups anew.")

    args = parser.parse_args()

    perform_lookup(
        args.input_file,
        args.output_file,
        max_workers=args.threads,
        throttle_delay=args.throttle,
        output_format=args.format,
        filter_private=args.filter_private,
        max_cache_age=args.max_cache_age,
        ignore_cache=args.ignore_cache
    )

