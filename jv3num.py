import re
import subprocess
import os
from concurrent.futures import ThreadPoolExecutor
import argparse
from urllib.parse import urlparse
from colorama import Fore, Style, init  # colorama for colored output

# Initialize colorama for colored output on all platforms
init(autoreset=True)

def is_valid_url(url):
    """Simple URL validation using regex."""
    regex = re.compile(
        r'^(https?://)'  # http or https at the start
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # OR ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # OR ipv6
        r'(?::\d+)?'  # port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None

def modify_urls(file_path, output_file):
    """Modify URLs from http to https, remove duplicates, and save to output file."""
    with open(file_path, 'r') as f:
        urls = set()  # Use a set to remove duplicates
        for line in f:
            url = line.strip()
            if is_valid_url(url):
                if url.startswith("http://"):
                    url = url.replace("http://", "https://")
                urls.add(url)  # Add to set (automatically handles duplicates)
    
    # Write the unique, modified URLs to the output file
    with open(output_file, 'w') as out_f:
        for url in sorted(urls):  # Sort the URLs for consistency
            out_f.write(url + '\n')

def run_command(command):
    """Helper function to run a shell command and capture the output."""
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(Fore.RED + f"Command failed: {command}")
    return result.stdout

def run_httpx_parallel(input_file, output_file, max_workers=20):
    """Run the httpx command to check for alive URLs in parallel."""
    print(Fore.MAGENTA + "[*] Running httpx...")

    def run_httpx_chunk(url_chunk):
        """Run httpx on a chunk of URLs."""
        command = f"echo '{url_chunk}' | httpx -silent"
        return run_command(command)

    with open(input_file, 'r') as f:
        urls = f.read().splitlines()

    url_chunks = [urls[i:i + max_workers] for i in range(0, len(urls), max_workers)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(run_httpx_chunk, ["\n".join(chunk) for chunk in url_chunks])

    # Write all alive URLs to the output file
    with open(output_file, 'w') as out_f:
        for result in results:
            out_f.write(result)

def has_subdomain(url):
    """Check if the URL has a subdomain (something before the main domain)."""
    parsed_url = urlparse(url)
    domain_parts = parsed_url.hostname.split('.')
    
    return len(domain_parts) > 2 and domain_parts[0] != 'www'

def clean_url(url):
    """Remove 'https://' or 'http://' and 'www.' from the URL."""
    parsed_url = urlparse(url)
    return parsed_url.hostname.replace('www.', '')  # Remove 'www.' if present

def sort_by_domain(url):
    """Sort subdomains based on the main domain."""
    parts = url.split('.')
    return '.'.join(parts[-2:])  # Sort by the main domain

def process_urls(file_path, no_subdomains_file, subdomains_file):
    with open(file_path, 'r') as f:
        no_subdomains = set()
        subdomains = set()
        
        for line in f:
            url = line.strip()
            if url:
                cleaned_url = clean_url(url)
                if has_subdomain(url):
                    subdomains.add(cleaned_url)
                else:
                    no_subdomains.add(cleaned_url)
    
    # Save URLs without subdomains
    with open(no_subdomains_file, 'w') as no_sub_f:
        for url in sorted(no_subdomains):
            no_sub_f.write(url + '\n')
    
    # Save URLs with subdomains
    with open(subdomains_file, 'w') as sub_f:
        for url in sorted(subdomains, key=sort_by_domain):
            sub_f.write(url + '\n')

def run_subfinder_parallel(input_file, output_file, max_workers=10):
    """Run subfinder on a list of domains in parallel by chunking the input."""
    print(Fore.YELLOW + "[*] Running subfinder...")

    def run_subfinder_chunk(url_chunk):
        command = f"echo '{url_chunk}' | subfinder -silent -dL /dev/stdin"
        return run_command(command)

    with open(input_file, 'r') as f:
        urls = f.read().splitlines()

    url_chunks = [urls[i:i + max_workers] for i in range(0, len(urls), max_workers)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(run_subfinder_chunk, ["\n".join(chunk) for chunk in url_chunks])

    with open(output_file, 'w') as out_f:
        for result in results:
            out_f.write(result)

def merge_alive_files(alive_domains_file, subdomains_alive_file, output_file):
    """Merge alive_domains.txt and alive_subdomains into alive_all.txt, adding 'https://' if not present."""
    urls = set()

    # Read alive domains
    with open(alive_domains_file, 'r') as domains_f:
        for line in domains_f:
            url = line.strip()
            if url:
                if not url.startswith("https://"):
                    url = f"https://{url}"
                urls.add(url)

    # Read alive subdomains
    with open(subdomains_alive_file, 'r') as subdomains_f:
        for line in subdomains_f:
            url = line.strip()
            if url:
                if not url.startswith("https://"):
                    url = f"https://{url}"
                urls.add(url)

    # Write merged URLs to alive_all.txt
    with open(output_file, 'w') as out_f:
        for url in sorted(urls):
            out_f.write(f"{url}\n")

def run_katana_and_gau_parallel(output_file, results_dir):
    """Run katana and gau in parallel, then merge results to find XSS-prone URLs."""
    katana_file = os.path.join(results_dir, 'katana.txt')
    gau_file = os.path.join(results_dir, 'gau.txt')
    xss_urls_file = os.path.join(results_dir, 'xssurls.txt')

    # Define the katana and gau commands
    katana_command = f"cat {output_file} | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl > {katana_file}"
    gau_command = f"cat {output_file} | gau > {gau_file}"

    # Use ThreadPoolExecutor to run katana and gau concurrently
    print(Fore.CYAN + "[*] Running katana and gau in parallel...", flush=True)
    with ThreadPoolExecutor(max_workers=2) as executor:
        katana_future = executor.submit(run_command, katana_command)
        gau_future = executor.submit(run_command, gau_command)

        # Wait for both commands to finish
        katana_result = katana_future.result()
        gau_result = gau_future.result()

    print(Fore.CYAN + "[*] katana and gau finished. Proceeding to merge results...", flush=True)

    # Merge katana and gau results, then run Gxss and kxss
    merge_and_find_xss(katana_file, gau_file, xss_urls_file)

def merge_and_find_xss(katana_file, gau_file, xss_urls_file):
    """Merge katana and gau results, run Gxss and kxss to find potential XSS-prone URLs."""
    print(Fore.CYAN + "[*] Finding potential XSS URLs with Gxss and kxss...", flush=True)
    merge_command = f"cat {katana_file} {gau_file} | Gxss | kxss > {xss_urls_file}"
    run_command(merge_command)

def cleanup_temp_files(files_to_remove):
    """Remove the specified temporary files."""
    print(Fore.RED + "[*] Removing temp files...")
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)

def ensure_unique_results_dir():
    """Ensure a unique 'results' directory. If it already exists, prompt for a new directory name."""
    results_dir = 'results'
    while os.path.exists(results_dir):
        print(f"The directory '{results_dir}' already exists.")
        results_dir = input("Please enter a new directory name: ")
    
    os.makedirs(results_dir)
    return results_dir

# Main Program:
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Subdomain finder and checker using subfinder and httpx')
    parser.add_argument('-u', '--urls', type=str, required=True, help='Input file containing URLs')
    parser.add_argument('-o', '--output', type=str, help='Specify the output directory')
    
    args = parser.parse_args()

    # Ensure a unique 'results' directory (or use provided output directory)
    if args.output:
        results_dir = args.output
        os.makedirs(results_dir, exist_ok=True)
    else:
        results_dir = ensure_unique_results_dir()

    # Set input file and output files within the 'results' directory
    file_path = args.urls
    output_file = os.path.join(results_dir, 'output_urls_remove.txt')
    alive_file = os.path.join(results_dir, 'alive_remove.txt')
    alive_domains_file = os.path.join(results_dir, 'alive_domains.txt')
    subdomains_file = os.path.join(results_dir, 'subdomains_remove.txt')
    subfinder_output_file = os.path.join(results_dir, 'subfinder_output_remove.txt')
    subdomains_alive_file = os.path.join(results_dir, 'alive_subdomains.txt')  # Alive subdomains after httpx
    merged_output_file = os.path.join(results_dir, 'alive_all.txt')  # Merged output

    # Step 1: Modify the URLs (change http to https, remove duplicates)
    print("[*] Fixing URLs")
    modify_urls(file_path, output_file)

    # Step 2: Check which URLs are alive using httpx (parallelized)
    run_httpx_parallel(output_file, alive_file, max_workers=30)

    # Step 3: Process the alive URLs (check for subdomains, clean and sort them)
    process_urls(alive_file, alive_domains_file, subdomains_file)

    # Step 4: Run subfinder in parallel on alive domains
    run_subfinder_parallel(alive_domains_file, subfinder_output_file, max_workers=30)

    # Step 5: Check which subdomains are alive using httpx
    run_httpx_parallel(subfinder_output_file, subdomains_alive_file, max_workers=30)

    # Step 6: Merge alive_domains.txt and alive_subdomains.txt into alive_all.txt
    print(Fore.MAGENTA + "Merging alive domains and subdomains into alive_all.txt...")
    merge_alive_files(alive_domains_file, subdomains_alive_file, merged_output_file)

    # Step 7: Run katana and gau concurrently, and merge results to find XSS-prone URLs
    run_katana_and_gau_parallel(merged_output_file, results_dir)

    # Step 8: Cleanup temporary files
    cleanup_temp_files([output_file, alive_file, subdomains_file, subfinder_output_file])

    print(Fore.CYAN + "All tasks completed :D H4ppy H4ck1ng")
