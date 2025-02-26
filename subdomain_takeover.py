import dns.resolver
import csv
import argparse
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Author: 0xNehru

# Known patterns for subdomain takeover vulnerabilities
TAKEOVER_PATTERNS = {
    "s3.amazonaws.com", "github.io", "herokuapp.com", "pantheon.io", "unbouncepages.com",
    "cloudfront.net", "tictail.com", "surge.sh", "bitbucket.io", "smugmug.com", "wordpress.com",
    "helpjuice.com", "helpscoutdocs.com", "amazonaws.com", "acquia-sites.com", "cargocollective.com",
    "flywheelstaging.com", "strikingly.com", "zendesk.com", "statuspage.io", "simplebooklet.com",
    "getresponse.com", "kinsta.com", "readme.io", "brightcove.com", "wufoo.com", "hatena.ne.jp",
    "activecampaign.com", "thinkific.com", "launchrock.com", "canny.io", "teamwork.com", "tilda.cc",
    "bigcartel.com", "aftership.com", "helpscout.net", "webflow.io", "ghost.io", "helprace.com"
}

# Function to resolve subdomain CNAME records
def resolve_subdomain(subdomain):
    """Resolves the CNAME record of a subdomain."""
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        return str(answers[0].target).rstrip(".")
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.Timeout:
        return "Timeout"
    except Exception as e:
        return f"Error: {str(e)}"

# Function to check if the CNAME target resolves to an A/AAAA record
def check_target_resolution(target):
    """Checks if a given CNAME target has an A/AAAA record."""
    try:
        dns.resolver.resolve(target, 'A')
        return True  # Resolved successfully
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return False
    except Exception:
        return False

# Function to check for subdomain takeover vulnerability
def check_takeover(subdomain, cname_target):
    """Determines if the subdomain is vulnerable to takeover."""
    if cname_target == "NXDOMAIN":
        return f"{Fore.RED}NXDOMAIN{Style.RESET_ALL}"

    if not cname_target:
        return "No CNAME record found"

    if check_target_resolution(cname_target):
        return "No takeover risk detected (CNAME resolved to an IP)"

    for pattern in TAKEOVER_PATTERNS:
        if pattern in cname_target:
            return f"{Fore.BLUE}Potential Takeover: {cname_target} (Unresolved){Style.RESET_ALL}"

    return "No takeover risk detected"

# Main function to process subdomains
def main(input_file, output_file):
    """Reads subdomains from file, checks takeover risks, and saves results."""
    results = []
    try:
        with open(input_file, 'r') as file:
            subdomains = [line.strip() for line in file if line.strip()]

        for subdomain in subdomains:
            cname_target = resolve_subdomain(subdomain)
            status = check_takeover(subdomain, cname_target)

            # Display NXDOMAIN results in red, others without color
            if cname_target == "NXDOMAIN":
                print(f"{Fore.RED}Checking {subdomain}... {status}{Style.RESET_ALL}")
            else:
                print(f"Checking {subdomain}... {status}")

            print(f"  CNAME: {cname_target or 'No CNAME'}\n")

            results.append({
                "subdomain": subdomain,
                "cname_target": cname_target or "No CNAME",
                "status": status
            })

        # Write results to CSV file
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Subdomain', 'CNAME Target', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

        print(f"{Fore.MAGENTA}Results saved to {output_file}{Style.RESET_ALL}")

    except FileNotFoundError:
        print(f"{Fore.RED}Error: Input file '{input_file}' not found.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Subdomain Takeover Checker")
    parser.add_argument("-l", "--list", required=True, help="Input file containing subdomains")
    parser.add_argument("-o", "--output", default="results.csv", help="Output CSV file (default: results.csv)")
    args = parser.parse_args()

    main(args.list, args.output)
