import subprocess
import os
from concurrent.futures import ThreadPoolExecutor
import argparse
from urllib.parse import urlparse
from colorama import Fore, Style, init  # colorama for colored output
import json  # For parsing ffuf output

init(autoreset=True)

def run_command(command):
    """Helper function to run a shell command and capture the output."""
    print(Fore.CYAN + f"Running command: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(Fore.RED + f"Command failed: {command}")
    return result.stdout

def extract_domain_for_ffuf(url):
    """Extract the main domain (second-level and top-level domain) from a URL."""
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    if domain:
        # Split the domain and return only the main domain (second-level and top-level domain)
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])  # Return only the main domain (e.g., example.com)
        else:
            return domain  # Return as is if it's already the main domain
    else:
        # If there's no scheme in the URL, it might be a raw domain, return it directly
        return url.strip()

def run_ffuf_on_provided_urls(input_file, wordlist_path, ffuf_output_file):
    """Run ffuf on the main domains provided in the input file."""
    print(Fore.GREEN + "[*] Running ffuf on provided URLs...")

    with open(input_file, 'r') as f:
        for url in f:
            url = url.strip()
            if url:
                main_domain = extract_domain_for_ffuf(url)
                ffuf_command = (
                    f"ffuf -u https://FUZZ.{main_domain} "
                    f"-w {wordlist_path} -mc 200,301,302,403 "
                    f"-o {ffuf_output_file} -of json"
                )
                run_command(ffuf_command)

def parse_ffuf_output(ffuf_output_file, parsed_output_file):
    """Parse the ffuf output JSON and extract the URLs into a text file."""
    print(Fore.MAGENTA + "[*] Parsing ffuf results...")

    with open(ffuf_output_file, 'r') as ffuf_f, open(parsed_output_file, 'w') as parsed_f:
        data = json.load(ffuf_f)
        for result in data.get('results', []):
            url = result['url']
            parsed_f.write(f"{url}\n")

    print(Fore.GREEN + f"[*] URLs extracted and saved to {parsed_output_file}")

def run_httpx(input_file, output_file, max_workers=20):
    print(Fore.MAGENTA + "[*] Running httpx...")

    def run_httpx_chunk(url_chunk):
        """Run httpx on a chunk of URLs."""
        command = f"echo '{url_chunk}' | httpx -silent"
        return run_command(command)

    with open(input_file, 'r') as f:
        urls = f.read().splitlines()

    if not urls:
        print(Fore.RED + f"[ERROR] No URLs to check with httpx. Skipping httpx.")
        return  # Skip if no URLs are found

    url_chunks = [urls[i:i + max_workers] for i in range(0, len(urls), max_workers)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(run_httpx_chunk, ["\n".join(chunk) for chunk in url_chunks])

    # Write all alive URLs to the output file
    with open(output_file, 'w') as out_f:
        for result in results:
            out_f.write(result)

def merge_and_normalize_files(ffuf_file, subfinder_file, merged_output_file):
    """Merge ffuf and subfinder files, normalize URLs, and remove duplicates."""
    urls = set()

    # Read ffuf URLs
    with open(ffuf_file, 'r') as ffuf_f:
        for line in ffuf_f:
            url = line.strip().lower()  # Normalize to lowercase
            if url:
                urls.add(url)

    # Read subfinder URLs
    with open(subfinder_file, 'r') as subfinder_f:
        for line in subfinder_f:
            url = line.strip().lower()  # Normalize to lowercase
            if url:
                urls.add(url)

    # Write deduplicated and normalized URLs to the merged output file
    with open(merged_output_file, 'w') as merged_f:
        for url in sorted(urls):
            merged_f.write(f"{url}\n")

    print(Fore.GREEN + f"[*] Merged and deduplicated URLs saved to {merged_output_file}")

def remove_duplicates_and_normalize(file_path):
    """Remove duplicates and normalize URLs by converting them to lowercase."""
    urls = set()

    # Read the file and normalize URLs to lowercase
    with open(file_path, 'r') as f:
        for line in f:
            url = line.strip().lower()  # Normalize to lowercase
            if url:
                urls.add(url)

    # Overwrite the file with deduplicated and normalized URLs
    with open(file_path, 'w') as out_f:
        for url in sorted(urls):
            out_f.write(f"{url}\n")

    print(Fore.GREEN + f"[*] Duplicates removed and URLs normalized in {file_path}")

def process_urls(file_path, no_subdomains_file, subdomains_file):
    """Process the URLs to separate subdomains and main domains."""
    with open(file_path, 'r') as f:
        no_subdomains = set()
        subdomains = set()
        
        for line in f:
            url = line.strip()
            if url:
                # Extract and clean the domain
                parsed_url = urlparse(url)
                cleaned_url = parsed_url.hostname.replace('www.', '') if parsed_url.hostname else url
                domain_parts = cleaned_url.split('.')

                # Check if it's a subdomain or a main domain
                if len(domain_parts) > 2:
                    subdomains.add(cleaned_url)
                else:
                    no_subdomains.add(cleaned_url)
    
    # Save URLs without subdomains
    with open(no_subdomains_file, 'w') as no_sub_f:
        for url in sorted(no_subdomains):
            no_sub_f.write(url + '\n')
    
    # Save URLs with subdomains
    with open(subdomains_file, 'w') as sub_f:
        for url in sorted(subdomains):
            sub_f.write(url + '\n')

def run_subfinder(input_file, output_file, max_workers=10):
    print(Fore.YELLOW + "[*] Running subfinder...")

    def run_subfinder_chunk(url_chunk):
        command = f"echo '{url_chunk}' | subfinder -silent -dL /dev/stdin"
        return run_command(command)

    with open(input_file, 'r') as f:
        urls = f.read().splitlines()

    if not urls:
        print(Fore.RED + f"[ERROR] No URLs found for subfinder.")
        return  # Skip if no URLs are found

    url_chunks = [urls[i:i + max_workers] for i in range(0, len(urls), max_workers)]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(run_subfinder_chunk, ["\n".join(chunk) for chunk in url_chunks])

    with open(output_file, 'w') as out_f:
        for result in results:
            out_f.write(result)

def run_katana_and_gau(output_file, results_dir):
    """Run katana and gau, then merge results to find XSS-prone URLs."""
    katana_file = os.path.join(results_dir, 'katana.txt')
    gau_file = os.path.join(results_dir, 'gau.txt')
    xss_urls_file = os.path.join(results_dir, 'xssurls.txt')

    katana_command = f"cat {output_file} | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl > {katana_file}"
    gau_command = f"cat {output_file} | gau > {gau_file}"

    # Use ThreadPoolExecutor to run katana and gau concurrently
    print(Fore.CYAN + "[*] Running katana and gau...", flush=True)
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
    """Merge results, run Gxss and kxss to find potential XSS URLs."""
    print(Fore.CYAN + "[*] Finding potential XSS URLs with Gxss and kxss...", flush=True)
    merge_command = f"cat {katana_file} {gau_file} | Gxss | kxss > {xss_urls_file}"
    run_command(merge_command)

def download_wordlist(wordlist_url, wordlist_path):
    if not os.path.exists(wordlist_path):
        print(Fore.CYAN + "[*] Downloading wordlist for ffuf...")
        run_command(f"wget {wordlist_url} -O {wordlist_path}")

def cleanup_temp_files(files_to_remove):
    print(Fore.RED + "[*] Removing temp files...")
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)

def ensure_unique_results_dir():
    results_dir = 'results'
    while os.path.exists(results_dir):
        print(f"The directory '{results_dir}' already exists.")
        results_dir = input("Please enter a new directory name: ")
    
    os.makedirs(results_dir)
    return results_dir

# Main Program:
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Subdomain finder and checker using subfinder, httpx, ffuf, katana, and gau')
    parser.add_argument('-u', '--urls', type=str, required=True, help='Input file containing URLs')
    parser.add_argument('-o', '--output', type=str, help='Specify the output directory')
    parser.add_argument('--skip', action='store_true', help='Skip running katana and gau')
    args = parser.parse_args()

    if args.output:
        results_dir = args.output
        os.makedirs(results_dir, exist_ok=True)
    else:
        results_dir = ensure_unique_results_dir()

    # Set input file and output files within the 'results' directory
    file_path = args.urls  # Input file provided by the user via -u
    alive_file = os.path.join(results_dir, 'alive_remove.txt')
    alive_domains_file = os.path.join(results_dir, 'alive_domains.txt')
    subdomains_file = os.path.join(results_dir, 'subdomains_remove.txt')
    subfinder_output_file = os.path.join(results_dir, 'subfinder_output_remove.txt')
    ffuf_remove_file = os.path.join(results_dir, 'ffuf_remove_file.txt')
    subdomains_alive_file = os.path.join(results_dir, 'alive_subdomains.txt')  # Alive subdomains after httpx
    merged_output_file = os.path.join(results_dir, 'alive_all.txt')  # Merged output from httpx
    ffuf_output_file = os.path.join(results_dir, 'ffuf_output.json')
    wordlist_url = "https://raw.githubusercontent.com/theMiddleBlue/DNSenum/refs/heads/master/wordlist/subdomains-top1mil-20000.txt"
    wordlist_path = os.path.join(results_dir, 'subdomains-top1mil-20000.txt')

    # Step 1: Check which URLs are alive using httpx (parallelized)
    run_httpx(file_path, alive_file, max_workers=30)

    # Step 2: Run ffuf on the main domains provided in the input file
    download_wordlist(wordlist_url, wordlist_path)
    run_ffuf_on_provided_urls(file_path, wordlist_path, ffuf_output_file)

    # Step 3: Parse ffuf output and save URLs to ffuf_remove_file.txt
    parse_ffuf_output(ffuf_output_file, ffuf_remove_file)

    # Step 4: Process the alive URLs (check for subdomains, clean and sort them)
    process_urls(alive_file, alive_domains_file, subdomains_file)

    # Step 5: Run subfinder on alive domains
    run_subfinder(alive_domains_file, subfinder_output_file, max_workers=30)

    # Step 6: Merge and normalize URLs from ffuf_remove_file.txt and subfinder_output_remove.txt
    merge_and_normalize_files(ffuf_remove_file, subfinder_output_file, subdomains_alive_file)

    # Step 7: Run httpx on the merged and normalized URLs and save the results to alive_subdomains.txt
    run_httpx(subdomains_alive_file, subdomains_alive_file, max_workers=30)

    # Step 8: Remove duplicates and normalize the final alive_subdomains.txt
    remove_duplicates_and_normalize(subdomains_alive_file)

    # Step 9: Optionally run katana and gau if --skip is not provided
    if not args.skip:
        run_katana_and_gau(subdomains_alive_file, results_dir)

    # Step 10: Cleanup temporary files
    cleanup_temp_files([alive_file, subdomains_file, subfinder_output_file, wordlist_path])

    print(Fore.CYAN + "All tasks completed :D H4ppy H4ck1ng")
