import dns.resolver
import csv
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

# Author: 0xNehru

# Known patterns for subdomain takeover vulnerabilities
takeover_patterns = [
    "s3.amazonaws.com",
    "github.io",
    "herokuapp.com",
    "pantheon.io",
    "unbouncepages.com",
    "cloudfront.net",
    "tictail.com",
    "surge.sh",
    "bitbucket.io",
    "smugmug.com",
    "wordpress.com",
    "helpjuice.com",
    "helpscoutdocs.com",
    "amazonaws.com",
    "acquia-sites.com",
    "cargocollective.com",
    "flywheelstaging.com",
    "strikingly.com",
    "zendesk.com",
    "statuspage.io",
    "simplebooklet.com",
    "getresponse.com",
    "kinsta.com",
    "readme.io",
    "brightcove.com",
    "wufoo.com",
    "hatena.ne.jp",
    "activecampaign.com",
    "thinkific.com",
    "launchrock.com",
    "canny.io",
    "cargocollective.com",
    "teamwork.com",
    "tilda.cc",
    "bigcartel.com",
    "aftership.com",
    "helpscout.net",
    "webflow.io",
    "ghost.io",
    "helprace.com",
]

# Function to resolve subdomain CNAME records
def resolve_subdomain(subdomain):
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except dns.resolver.NoAnswer:
        return "No CNAME record found"
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.Timeout:
        return "Timeout"
    except Exception as e:
        return f"Error: {str(e)}"

# Function to check if the CNAME target resolves to an A/AAAA record
def check_target_resolution(target):
    try:
        answers = dns.resolver.resolve(target, 'A')
        return [rdata.address for rdata in answers]  # Return list of resolved IPs
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.Timeout:
        return None
    except Exception:
        return None

# Function to check for subdomain takeover
def check_takeover(subdomain, cname_target):
    if cname_target == "NXDOMAIN" or cname_target == "No CNAME record found":
        return "Not Vulnerable"
    
    resolved_ips = check_target_resolution(cname_target)
    if resolved_ips:
        return "No takeover risk detected (CNAME resolved to IPs)"
    
    for pattern in takeover_patterns:
        if pattern in cname_target:
            return f"{Fore.BLUE}Potential Takeover: {cname_target} (NXDOMAIN or unresolved){Style.RESET_ALL}"
    
    return "No takeover risk detected"

# Main function to process subdomains from file
def main(input_file, output_file):
    results = []
    try:
        with open(input_file, 'r') as file:
            subdomains = file.read().splitlines()

        for subdomain in subdomains:
            print(f"Checking {subdomain}...")
            cname_target = resolve_subdomain(subdomain)
            status = check_takeover(subdomain, cname_target)

            results.append({
                "subdomain": subdomain,
                "cname_target": cname_target,
                "status": status
            })

            print(f"  CNAME: {cname_target}")
            print(f"  Status: {status}\n")

        # Write results to CSV file
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Subdomain', 'CNAME Target', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in results:
                writer.writerow({
                    'Subdomain': result['subdomain'],
                    'CNAME Target': result['cname_target'],
                    'Status': result['status']
                })

        print(f"Results saved to {output_file}")

    except FileNotFoundError:
        print(f"Input file {input_file} not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    input_file = "urls.txt"  # Replace with your input file name
    output_file = "results.csv"  # Replace with your desired output file name
    main(input_file, output_file)
