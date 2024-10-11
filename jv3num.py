import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from colorama import Fore, init
import argparse
import os
import logging
import requests
import time

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging for better control over output levels
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def run_ssl_scan(domain, ssl_output_file):
    """
    Generate the SSL Labs scan URL for a given domain and save it to a file.
    """
    result_url = f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}&hideResults=on"
    logging.info(f"Generated SSL scan URL: {result_url}")

    try:
        with open(ssl_output_file, 'a') as f_ssl:
            f_ssl.write(result_url + '\n')  # Save the URL to the file with a newline
        logging.info(f"Saved SSL scan URL for {domain}")
    except IOError as e:
        logging.error(f"[ERROR] Failed to write SSL scan results for {domain}: {e}")


def run_httpx(domains, urls_output_file, domains_output_file, ssl_output_file, max_workers=5):
    """
    Run httpx for multiple domains, trigger SSL scan for each domain, and save the output to files.
    """
    with open(urls_output_file, 'w'), open(domains_output_file, 'w'), open(ssl_output_file, 'w'):
        pass  # Clear the files before appending results

    def process_domain(domain):
        command = f"echo '{domain}' | httpx -silent"
        logging.info(f"Running command: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        if result.returncode == 0 and result.stdout.strip():
            with open(urls_output_file, 'a') as f_urls, open(domains_output_file, 'a') as f_domains:
                f_urls.write(result.stdout + '\n')
                for url in result.stdout.splitlines():
                    parsed_domain = urlparse(url).netloc
                    f_domains.write(parsed_domain + '\n')

                logging.info(f"Saved output for {domain} to {urls_output_file} and {domains_output_file}")

            # Generate and save SSL Labs scan URL for the domain
            run_ssl_scan(domain, ssl_output_file)

        else:
            logging.error(f"[ERROR] No valid output for {domain} or command failed.")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(process_domain, domains)


def run_subdomain_passive(domains_file, subdomains_output_file, max_workers=5):
    """Run subfinder and assetfinder for multiple domains, and append sorted unique subdomains to a file."""
    with open(subdomains_output_file, 'w'):
        pass  # Clear the file before appending results

    def process_subdomain(domain):
        command = f"echo '{domain}' | subfinder -silent | assetfinder -subs-only | sort -u"
        logging.info(f"Running command: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            with open(subdomains_output_file, 'a') as f_subdomains:
                f_subdomains.write(result.stdout + '\n')
            logging.info(f"Subdomains found for {domain} and saved to {subdomains_output_file}")
        else:
            logging.error(f"[ERROR] Subdomain passive enumeration failed for {domain} or no valid subdomains found.")

    # Read domains from the file
    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(process_subdomain, domains)


def run_subdomain_active(domains_file, ffuf_output_file, all_subdomains_file, alive_subdomains_file, max_workers=5):
    """Run ffuf for subdomain brute-forcing, process results, run httpx, and clean up files."""
    
    # Ensure the wordlist is downloaded, if not, download it
    wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt"
    wordlist_file = os.path.join(os.path.dirname(ffuf_output_file), "subdomains-top1million-110000.txt")

    if not os.path.exists(wordlist_file):
        logging.info(f"[*] Downloading wordlist for subdomain brute-forcing: {wordlist_file}")
        subprocess.run(f"wget {wordlist_url} -O {wordlist_file}", shell=True, check=True)
    else:
        logging.info(f"[*] Wordlist already exists: {wordlist_file}")

    def process_domain(domain):
        # Run ffuf and save output as JSON into ffuf_output_file
        command = f'ffuf -u "https://FUZZ.{domain}" -w {wordlist_file} -mc 200,301,302,401,403,500 -o {ffuf_output_file} -of json -t 80'
        logging.info(f"Running ffuf for domain: {domain}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=3600)

        if result.returncode == 0:
            logging.info(f"ffuf command completed successfully for {domain}")
        else:
            logging.error(f"[ERROR] ffuf failed for {domain}: {result.stderr}")
            return

        # Now parse the ffuf output (saved in ffuf_output_file) to extract subdomains
        try:
            with open(ffuf_output_file, 'r') as f:
                ffuf_output = json.load(f)  # Load the JSON output

            found_subdomains = set()

            # Extract the "host" value (subdomains) from each result entry
            for entry in ffuf_output.get("results", []):
                found_subdomains.add(entry["host"].lower())  # Normalize to lowercase

            # Append found subdomains to all_subdomains_file
            with open(all_subdomains_file, 'a') as f_subdomains:
                f_subdomains.write('\n'.join(found_subdomains) + '\n')

            logging.info(f"Brute-force subdomains for {domain} saved to {all_subdomains_file}")
        except (json.JSONDecodeError, FileNotFoundError) as e:
            logging.error(f"[ERROR] Failed to parse or find ffuf output for {domain}: {e}")

    # Read domains from the domains_file (alive_domains.txt)
    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    # Run ffuf brute force for each domain
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(process_domain, domains)

    # Run httpx on the subdomains saved in all_subdomains.txt
    try:
        logging.info(f"[*] Running httpx on all_subdomains.txt to identify alive subdomains.")
        httpx_command = f"cat {all_subdomains_file} | httpx -silent > {alive_subdomains_file}"
        subprocess.run(httpx_command, shell=True, check=True)
        logging.info(f"[*] httpx completed. Results saved to {alive_subdomains_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] httpx command failed: {e}")
        return

    # Clean up temporary files
    try:
        logging.info(f"[*] Removing temporary files: {ffuf_output_file}, {wordlist_file}, {all_subdomains_file}")
        os.remove(ffuf_output_file)
        os.remove(wordlist_file)
        logging.info("[*] Cleanup completed successfully.")
    except OSError as e:
        logging.error(f"[ERROR] Failed to remove files: {e}")

    logging.info(f"Subdomains processed and alive subdomains saved in {alive_subdomains_file}")


def main():
    parser = argparse.ArgumentParser(description="Run httpx, SSL scan, and subdomain enumeration on a list of domains.")
    parser.add_argument('-l', '--list', type=str, required=True, help="File containing a list of domains to scan with httpx")
    parser.add_argument('-o', '--output', type=str, help="Directory to save the output files (alive_urls.txt, alive_domains.txt, ssl_scan_results.txt)")

    args = parser.parse_args()

    output_dir = args.output if args.output else '.'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"[*] Created directory: {output_dir}")

    urls_output_file = os.path.join(output_dir, 'alive_urls.txt')
    domains_output_file = os.path.join(output_dir, 'alive_domains.txt')
    ssl_output_file = os.path.join(output_dir, 'ssl_scan_results.txt')
    ffuf_output_file = os.path.join(output_dir, 'ffuf.txt')
    all_subdomains_file = os.path.join(output_dir, 'all_subdomains.txt')
    alive_subdomains_file = os.path.join(output_dir, 'alive_subdomains.txt')

    # Step 1: Run httpx on the provided list of domains
    if not os.path.exists(args.list):
        logging.error(f"[ERROR] File not found: {args.list}")
        return

    with open(args.list, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    if not domains:
        logging.error("[ERROR] No valid domains found in the list.")
        return

    run_httpx(domains, urls_output_file, domains_output_file, ssl_output_file)

    # Step 2: Run passive subdomain enumeration
    logging.info(f"[*] Running subdomain passive enumeration on domains from {domains_output_file}")
    run_subdomain_passive(domains_output_file, all_subdomains_file)

    # Step 3: Run active subdomain brute-forcing using ffuf
    logging.info(f"[*] Running active subdomain brute-forcing")
    run_subdomain_active(domains_output_file, ffuf_output_file, all_subdomains_file, alive_subdomains_file, max_workers=5)


if __name__ == "__main__":
    main()
