import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from colorama import Fore, init
import argparse
import os
import logging
import requests
import json
import shutil

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging for better control over output levels
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def run_command(command, capture_output=True, check=False, timeout=None):
    """Utility function to run shell commands."""
    try:
        logging.info(f"Executing command: {command}")
        result = subprocess.run(command, shell=True, capture_output=capture_output, text=True, timeout=timeout, check=check)
        if result.returncode != 0:
            logging.error(f"Command failed: {command}\nError: {result.stderr.strip()}")
        return result.stdout.strip() if capture_output else result.returncode
    except subprocess.CalledProcessError as e:
        logging.error(f"Command '{command}' failed with error: {e}")
        return None

def save_to_file(filepath, data, mode='a'):
    """Utility function to save data to a file."""
    try:
        with open(filepath, mode) as f:
            f.write(data + '\n')
        logging.info(f"Data saved to {filepath}")
    except IOError as e:
        logging.error(f"Failed to write to file {filepath}: {e}")

def run_httpx(domains, urls_output_file, domains_output_file, ssl_output_file, max_workers=5):
    """Run httpx for multiple domains and save the output to a file."""
    with open(urls_output_file, 'w'), open(domains_output_file, 'w'):
        pass  # Clear the files before appending results

    def process_domain(domain):
        result = run_command(f"echo '{domain}' | httpx -silent")
        if result:
            save_to_file(urls_output_file, result)
            for url in result.splitlines():
                parsed_domain = urlparse(url).netloc
                save_to_file(domains_output_file, parsed_domain)
                run_ssl_scan(parsed_domain, ssl_output_file)
        else:
            logging.error(f"No valid output for {domain}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(process_domain, domains)

def run_ssl_scan(domain, ssl_output_file):
    """Generate the SSL Labs scan URL for a given domain, trigger the scan, and save it to a file."""
    result_url = f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}&hideResults=on"
    
    # Trigger the SSL Labs scan by sending a request to the URL
    try:
        logging.info(f"Triggering SSL scan for {domain} at {result_url}")
        requests.get(result_url)
    except requests.RequestException as e:
        logging.error(f"Failed to trigger SSL scan for {domain}: {e}")
    
    # Save the scan URL to the ssl_output_file
    save_to_file(ssl_output_file, result_url)

def run_subdomain_passive(domains_file, subdomains_output_file, max_workers=5):
    """Run subfinder and assetfinder for multiple domains, and append sorted unique subdomains to a file."""
    with open(subdomains_output_file, 'w'):
        pass  # Clear the file before appending results

    def process_subdomain(domain):
        subfinder_result = run_command(f"echo '{domain}' | subfinder -silent")
        assetfinder_result = run_command(f"echo '{domain}' | assetfinder -subs-only")

        if subfinder_result or assetfinder_result:
            subdomains = set(subfinder_result.splitlines() if subfinder_result else []) | \
                         set(assetfinder_result.splitlines() if assetfinder_result else [])
            if subdomains:
                save_to_file(subdomains_output_file, '\n'.join(sorted(subdomains)))
            else:
                logging.error(f"No subdomains found for {domain}.")
        else:
            logging.error(f"Subdomain tools failed for {domain}.")

    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(process_subdomain, domains)

def run_subdomain_active(domains_file, ffuf_output_file, all_subdomains_file, alive_subdomains_file, max_workers=5):
    """Run ffuf for subdomain brute-forcing, process results, run httpx, and clean up files."""
    
    wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt"
    wordlist_file = os.path.join(os.path.dirname(ffuf_output_file), "subdomains-top1million-110000.txt")

    # Ensure the wordlist is downloaded
    if not os.path.exists(wordlist_file):
        run_command(f"wget {wordlist_url} -O {wordlist_file}", capture_output=False, check=True)

    def process_domain(domain):
        command = f'ffuf -u "https://FUZZ.{domain}" -w {wordlist_file} -mc 200,301,302,401,403,500 -o {ffuf_output_file} -of json -t 80'
        result = run_command(command, timeout=3600)
        if result:
            try:
                with open(ffuf_output_file, 'r') as f:
                    ffuf_output = json.load(f)
                found_subdomains = {entry["host"].lower() for entry in ffuf_output.get("results", [])}
                if found_subdomains:
                    save_to_file(all_subdomains_file, '\n'.join(found_subdomains))
            except (json.JSONDecodeError, FileNotFoundError) as e:
                logging.error(f"Failed to parse ffuf output for {domain}: {e}")

    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(process_domain, domains)

    # Run httpx on the subdomains saved in all_subdomains.txt
    run_command(f"cat {all_subdomains_file} | httpx -silent > {alive_subdomains_file}", capture_output=False, check=True)

    # Clean up
    for temp_file in [ffuf_output_file, wordlist_file]:
        try:
            os.remove(temp_file)
        except OSError as e:
            logging.error(f"Failed to remove file {temp_file}: {e}")

def run_favicon_scan(domains_file, favicons_dir):
    """Download and run FavFreak for favicon analysis, save output, and clean up."""
    favfreak_repo = "https://raw.githubusercontent.com/jvs3c/FavFreak_jvs3c/master/favfreak.py"
    favfreak_script = os.path.join(favicons_dir, "favfreak.py")
    favicons_output = os.path.join(favicons_dir, "favicons.txt")

    # Create directory for FavFreak if it doesn't exist
    os.makedirs(favicons_dir, exist_ok=True)

    # Download favfreak.py script
    run_command(f"wget {favfreak_repo} -O {favfreak_script}", capture_output=False, check=True)

    # Run FavFreak tool on the domains file
    run_command(f"cat {domains_file} | python3 {favfreak_script} > {favicons_output}", capture_output=False, check=True)

    # Remove the FavFreak script after running the tool
    try:
        os.remove(favfreak_script)
        logging.info(f"Removed FavFreak script: {favfreak_script}")
    except OSError as e:
        logging.error(f"Failed to remove file {favfreak_script}: {e}")

class SubdomainTakeoverDetector:
    def __init__(self, subdomains_output_file, nuclei_output, nuclei_template_dir, subzy_output, output_dir):
        self.subfinder_output = subdomains_output_file
        self.nuclei_output = nuclei_output
        self.subzy_output = subzy_output
        self.nuclei_template_dir = nuclei_template_dir
        self.output_dir = output_dir

        if not os.path.exists(nuclei_template_dir):
            raise FileNotFoundError(f"Nuclei template directory not found: {nuclei_template_dir}")

    def run_nuclei_takeover_scan(self):
        """Run Nuclei with takeover templates on the identified subdomains."""
        nuclei_output_path = os.path.join(self.output_dir, "subdomain_takeover", self.nuclei_output)
        os.makedirs(os.path.dirname(nuclei_output_path), exist_ok=True)

        nuclei_command = f"nuclei -l {self.subfinder_output} -t {self.nuclei_template_dir} -o {nuclei_output_path} -silent"
        run_command(nuclei_command, capture_output=False, check=True)

    def run_subzy_takeover_scan(self):
        """Run Subzy with takeover templates on the identified subdomains."""
        subzy_output_path = os.path.join(self.output_dir, "subdomain_takeover", self.subzy_output)
        os.makedirs(os.path.dirname(subzy_output_path), exist_ok=True)

        subzy_command = f"subzy -targets {self.subfinder_output} > {subzy_output_path}"
        run_command(subzy_command, capture_output=False, check=True)

    def run_takeover_detection(self):
        self.run_nuclei_takeover_scan()
        self.run_subzy_takeover_scan()

def main():
    parser = argparse.ArgumentParser(description="Run httpx, passive and active subdomain enumeration on a list of domains.")
    parser.add_argument('-l', '--list', type=str, required=True, help="File containing a list of domains to scan with httpx")
    parser.add_argument('-o', '--output', type=str, help="Directory to save the output files (alive_urls.txt, alive_domains.txt, ssl_scan_results.txt, etc.)")

    args = parser.parse_args()

    output_dir = args.output if args.output else '.'
    os.makedirs(output_dir, exist_ok=True)

    # Create an SSL folder
    ssl_dir = os.path.join(output_dir, 'ssl')
    os.makedirs(ssl_dir, exist_ok=True)
    ssl_output_file = os.path.join(ssl_dir, 'ssl_scan_results.txt')

    # Create a favicon folder
    favicons_dir = os.path.join(output_dir, 'favicons')
    os.makedirs(favicons_dir, exist_ok=True)

    urls_output_file = os.path.join(output_dir, 'alive_urls.txt')
    domains_output_file = os.path.join(output_dir, 'alive_domains.txt')
    ffuf_output_file = os.path.join(output_dir, 'ffuf.txt')
    all_subdomains_file = os.path.join(output_dir, 'all_subdomains.txt')
    alive_subdomains_file = os.path.join(output_dir, 'alive_subdomains.txt')
    nuclei_output = 'nuclei_takeover_results.txt'
    subzy_output = 'subzy_takeover_results.txt'
    nuclei_template_dir = "/home/jon/nuclei-templates/http/takeovers/"

    if not os.path.exists(args.list):
        logging.error(f"File not found: {args.list}")
        return
    
    with open(args.list, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    if not domains:
        logging.error("No valid domains found in the list.")
        return

    run_httpx(domains, urls_output_file, domains_output_file, ssl_output_file)

    logging.info(f"Running subdomain passive enumeration on domains from {domains_output_file}")
    run_subdomain_passive(domains_output_file, all_subdomains_file)

    logging.info(f"Running active subdomain brute-forcing")
    run_subdomain_active(domains_output_file, ffuf_output_file, all_subdomains_file, alive_subdomains_file, max_workers=5)

    logging.info(f"Running subdomain takeover detection")
    takeover_detector = SubdomainTakeoverDetector(
        alive_subdomains_file, nuclei_output, nuclei_template_dir, subzy_output, output_dir
    )
    takeover_detector.run_takeover_detection()

    # Run favicon search using FavFreak after active subdomain enumeration
    logging.info(f"Running favicon scan using FavFreak")
    run_favicon_scan(alive_subdomains_file, favicons_dir)

if __name__ == "__main__":
    main()
