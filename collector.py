__Name__ = "Collector"
__Description__ = "Collect XSS vulnerable parameters from entire domain."
__Author__ = "Md. Nur Habib & Charles Norris"
__Version__ = "1.0.1"

import argparse
import multiprocessing
import os
import requests
import socket
import sys
import urllib.parse
import warnings
from multiprocessing import Manager
from plugins.banner import display_banner  # Assuming 'Bannerfunction' was renamed to 'display_banner'

# Suppress warnings for cleaner output
warnings.filterwarnings("ignore")

# Display banner function call (improved naming)
display_banner()

# Argument parsing with improved formatting and help descriptions
parser = argparse.ArgumentParser(description="=============== Help Menu ===============")
parser.add_argument("function", help="`pull` or `check`")
parser.add_argument("--host", help="Domain/Host Name")
parser.add_argument("--threads", help="The number of threads", default=5, type=int)
parser.add_argument("--with-subs", help="`yes` or `no`", default=True, type=bool)
parser.add_argument("--loadfile", help="File location")
parser.add_argument("--outputfile", help="Saving Path")

args = parser.parse_args()

def get_wayback_urls(host, include_subdomains):
    """Retrieve URLs from Wayback Machine."""
    # URL conditional formatting based on subdomain inclusion
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{host}/*&output=list&fl=original&collapse=urlkey" if include_subdomains else f"http://web.archive.org/cdx/search/cdx?url={host}/*&output=list&fl=original&collapse=urlkey"
    response = requests.get(url)
    
    # Save output to file if specified by user
    if args.outputfile:
        with open(args.outputfile, "w") as file:
            file.write(response.text.strip())
    print(response.text.strip())

def check_domain(url):
    """Check if the provided domain URL is accessible."""
    # Basic checks and sanitization
    if not url:
        return
    url = url.replace(":80/", "/").replace(":443/", "/")
    if not url.startswith("http"):
        url = f"http://{url}"
    domain = urllib.parse.urlparse(url).netloc.split(":")[0]

    # Skip if domain already encountered
    if domain in timeout_domains:
        return
    try:
        # Short timeout to prevent hanging requests
        response = requests.head(url, verify=False, timeout=0.25)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
        # Add to timeout list if inaccessible
        timeout_domains.append(domain)
        return
    except requests.exceptions.RequestException:
        timeout_domains.append(domain)
        return

    # Check for redirection to HTTPS
    if response.status_code // 100 == 3 and url.startswith("http://") and response.headers.get("Location", "").startswith("https://"):
        try:
            # Try HTTPS version if HTTP redirects
            response = requests.head(f"https{url[4:]}", verify=False, timeout=0.25)
        except requests.exceptions.RequestException:
            return

    # Get Content-Length and Content-Type or assign "Unknown"
    content_length = response.headers.get("Content-Length", "Unknown")
    content_type = response.headers.get("Content-Type", "Unknown")

    # Format result for output
    result = ", ".join([url, str(response.status_code), content_length, content_type])
    if args.outputfile:
        write_queue.put(result + "\n")
    print(result)

def validate_domains(endpoints):
    """Filter valid domain URLs from a list of endpoints."""
    valid_domains = set()
    invalid_domains = set()
    valid_endpoints = []

    # Improved loop with direct use of stripped endpoints
    for endpoint in endpoints:
        endpoint = endpoint.strip().strip('"').strip("'")
        try:
            parsed_url = urllib.parse.urlparse(endpoint)
            domain = parsed_url.netloc.split(":")[0]

            # Avoid duplicate DNS lookups
            if domain in valid_domains:
                valid_endpoints.append(endpoint)
            elif domain not in invalid_domains:
                try:
                    socket.gethostbyname(domain)
                    valid_domains.add(domain)
                    valid_endpoints.append(endpoint)
                except socket.gaierror:
                    invalid_domains.add(domain)
        except ValueError:
            continue

    return valid_endpoints

def write_output(file):
    """Write output to a file from the queue."""
    while True:
        line = write_queue.get()
        if line is None:  # End writing when None is reached
            break
        file.write(line)

# Set up multiprocessing with Manager to manage shared resources
manager = Manager()
timeout_domains = manager.list()  # Shared list for timed-out domains
write_queue = manager.Queue()     # Queue for file writing
pool = multiprocessing.Pool(args.threads)

if args.function == "pull":
    # Fetch URLs from Wayback if 'pull' function is selected
    if args.host:
        print('\nFetching URLs, please wait...\n')
        get_wayback_urls(args.host, args.with_subs)
    elif args.loadfile:
        # Load hosts from a file
        with open(args.loadfile) as file:
            for line in file:
                get_wayback_urls(line.strip(), args.with_subs)

elif args.function == "check":
    # Check domains if 'check' function is selected
    if args.loadfile:
        try:
            if args.outputfile:
                with open(args.outputfile, "w", buffering=1) as output_file:
                    # Start a separate process for writing to file
                    writer_process = multiprocessing.Process(target=write_output, args=(output_file,))
                    writer_process.start()

                # Validate and filter endpoints
                endpoints = validate_domains(open(args.loadfile).readlines())
                # Use multiprocessing pool to check each domain
                pool.map(check_domain, endpoints)

                if args.outputfile:
                    write_queue.put(None)  # Signal to stop writing
                    writer_process.join()
        except IOError:
            print("File not found!")
            sys.exit(1)
        except KeyboardInterrupt:
            print("Killing processes.")
            pool.terminate()
            sys.exit(1)
    elif not sys.stdin.isatty():
        try:
            if args.outputfile:
                with open(args.outputfile, "w", buffering=1) as output_file:
                    writer_process = multiprocessing.Process(target=write_output, args=(output_file,))
                    writer_process.start()

                endpoints = validate_domains(sys.stdin.readlines())
                pool.map(check_domain, endpoints)

                if args.outputfile:
                    write_queue.put(None)
                    writer_process.join()
        except IOError:
            print("File not found!")
            sys.exit(1)
        except KeyboardInterrupt:
            print("Killing processes.")
            pool.terminate()
            sys.exit(1)
else:
    print("Please specify a file.")
    sys.exit(1)
