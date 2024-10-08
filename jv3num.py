import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from colorama import Fore, init
import argparse
import os
import logging

# Initialize colorama for colored output
init(autoreset=True)

# Set up logging for better control over output levels
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def run_httpx(domains, urls_output_file, domains_output_file, max_workers=5):
    """Run httpx for multiple domains and save the output to a file."""
    with open(urls_output_file, 'w'), open(domains_output_file, 'w'):
        pass  # Clear the files before appending results

    def process_domain(domain):
        command = f"echo '{domain}' | httpx -silent"
        logging.info(f"Running command: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            with open(urls_output_file, 'a') as f_urls, open(domains_output_file, 'a') as f_domains:
                f_urls.write(result.stdout + '\n')
                for url in result.stdout.splitlines():
                    domain = urlparse(url).netloc
                    f_domains.write(domain + '\n')
            logging.info(f"Saved output for {domain} to {urls_output_file} and {domains_output_file}")
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

def run_subdomain_active(domains_file, ffuf_output_file, max_workers=5):
    """Run puredns for subdomain brute-forcing and append results to a file."""
    with open(ffuf_output_file, 'w'):
        pass  # Clear the file before appending results

    # Ensure the wordlist is downloaded, if not, download it
    wordlist_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt"
    wordlist_file = os.path.join(os.path.dirname(ffuf_output_file), "subdomains-top1million-110000.txt")

    if not os.path.exists(wordlist_file):
        logging.info(f"[*] Downloading wordlist for subdomain brute-forcing: {wordlist_file}")
        subprocess.run(f"wget {wordlist_url} -O {wordlist_file}", shell=True, check=True)
    else:
        logging.info(f"[*] Wordlist already exists: {wordlist_file}")

    def process_domain(domain):
        command = f'ffuf -u "https://FUZZ.{domain}" -w {wordlist_file} -mc 200,301,302,401,403,500 -o {ffuf_output_file} -t 80'
        logging.info(f"Running ffuf for domain: {domain}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=3600)
        if result.returncode == 0 and result.stdout.strip():
            with open(ffuf_output_file, 'a') as f_subdomains:
                f_subdomains.write(result.stdout + '\n')
            logging.info(f"Brute-force subdomains for {domain} saved to {ffuf_output_file}")
        else:
            logging.error(f"[ERROR] ffuf failed for {domain}")

    # Read domains from the domains_file (alive_domains.txt)
    with open(domains_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    # Run ffuf brute force for each domain
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(process_domain, domains)

    # Sort and remove duplicates from the output file
    alive_subdomains_file = os.path.join(os.path.dirname(ffuf_output_file), "alive_subdomains.txt")
    if os.path.exists(ffuf_output_file):
        with open(ffuf_output_file, 'r') as f:
            new_subdomains = set(f.read().splitlines())

        if os.path.exists(alive_subdomains_file):
            with open(alive_subdomains_file, 'r') as f:
                existing_subdomains = set(f.read().splitlines())
        else:
            existing_subdomains = set()

        all_subdomains = sorted(new_subdomains.union(existing_subdomains))
        with open(alive_subdomains_file, 'w') as f:
            f.write('\n'.join(all_subdomains))

        logging.info(f"Subdomains from brute-forcing added and sorted in {alive_subdomains_file}")
    else:
        logging.error(f"[ERROR] ffuf output file {ffuf_output_file} not found.")

class SubdomainTakeoverDetector:
    def __init__(self, domain_file, subdomains_output_file, nuclei_output, nuclei_template_dir):
        self.domain_file = domain_file  # Alive domains file to pass to subfinder
        self.subfinder_output = subdomains_output_file  # Output file for subfinder results
        self.nuclei_output = nuclei_output  # Output file for nuclei results
        self.nuclei_template_dir = nuclei_template_dir  # Directory for the Nuclei templates

        # Check if the Nuclei templates directory exists
        if not os.path.exists(nuclei_template_dir):
            logging.error(f"Nuclei template directory not found: {nuclei_template_dir}")
            raise FileNotFoundError(f"Nuclei template directory not found: {nuclei_template_dir}")
        logging.info(f"Nuclei template directory found: {nuclei_template_dir}")

    def run_nuclei_takeover_scan(self):
        """Run Nuclei with takeover templates on the identified subdomains."""
        if not os.path.exists(self.subfinder_output):
            logging.error(f"Subfinder output file not found: {self.subfinder_output}")
            raise FileNotFoundError(f"Subfinder output file not found: {self.subfinder_output}")

        nuclei_command = f"nuclei -l {self.subfinder_output} -t {self.nuclei_template_dir} -o {self.nuclei_output}"
        logging.info(f"Running Nuclei for Subdomain Takeover Detection: {nuclei_command}")

        try:
            subprocess.run(nuclei_command, shell=True, check=True)
            logging.info(f"Nuclei completed. Results saved to {self.nuclei_output}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Nuclei scan failed: {e}")
            raise

    def run_takeover_detection(self):
        """Run the entire subdomain takeover detection process."""
        logging.info("Starting Subdomain Takeover Detection Process")
        self.run_nuclei_takeover_scan()

def main():
    parser = argparse.ArgumentParser(description="Run httpx, passive and active subdomain enumeration on a list of domains.")
    parser.add_argument('-l', '--list', type=str, required=True, help="File containing a list of domains to scan with httpx")
    parser.add_argument('-o', '--output', type=str, help="Directory to save the output files (alive_urls.txt, alive_domains.txt, and all_subdomains.txt)")

    args = parser.parse_args()

    output_dir = args.output if args.output else '.'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.info(f"[*] Created directory: {output_dir}")

    urls_output_file = os.path.join(output_dir, 'alive_urls.txt')
    domains_output_file = os.path.join(output_dir, 'alive_domains.txt')
    ffuf_output_file = os.path.join(output_dir, 'ffuf.txt')
    subdomains_output_file = os.path.join(output_dir, 'all_subdomains.txt')
    alive_subdomains_file = os.path.join(output_dir, 'alive_subdomains.txt')

    nuclei_template_dir = "/home/jon/nuclei-templates/http/takeovers/"  # Nuclei templates for subdomain takeover detection
    nuclei_output = os.path.join(output_dir, 'nuclei_takeover_results.txt')

    # Step 1: Run httpx on the provided list of domains
    if not os.path.exists(args.list):
        logging.error(f"[ERROR] File not found: {args.list}")
        return
    
    with open(args.list, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    if not domains:
        logging.error("[ERROR] No valid domains found in the list.")
        return

    run_httpx(domains, urls_output_file, domains_output_file)

    # Step 2: Run passive subdomain enumeration
    logging.info(f"[*] Running subdomain passive enumeration on domains from {domains_output_file}")
    run_subdomain_passive(domains_output_file, subdomains_output_file)

    # Step 3: Run active subdomain brute-forcing using shuffledns and ffuf
    logging.info(f"[*] Running active subdomain brute-forcing")
    run_subdomain_active(domains_output_file, ffuf_output_file, max_workers=5)

    # Step 4: Run subdomain takeover detection using subfinder and nuclei
    logging.info(f"[*] Running subdomain takeover detection")
    takeover_detector = SubdomainTakeoverDetector(domains_output_file, subdomains_output_file, nuclei_output, nuclei_template_dir)
    takeover_detector.run_takeover_detection()

if __name__ == "__main__":
    main()
