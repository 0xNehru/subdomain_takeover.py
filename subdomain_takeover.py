import dns.resolver
import csv

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

# Function to check for subdomain takeover
def check_takeover(target):
    if target == "NXDOMAIN" or target == "No CNAME record found":
        return "Not Vulnerable"
    for pattern in takeover_patterns:
        if pattern in target:
            return f"Potential Takeover: {pattern}"
    return "No takeover risk detected"

# Main function to process subdomains from file
def main(input_file, output_file):
    results = []
    try:
        with open(input_file, 'r') as file:
            subdomains = file.read().splitlines()

        for subdomain in subdomains:
            print(f"Checking {subdomain}...")
            target = resolve_subdomain(subdomain)
            status = check_takeover(target)

            results.append({
                "subdomain": subdomain,
                "target": target,
                "status": status
            })
            print(f"  CNAME: {target}")
            print(f"  Status: {status}\n")

        # Write results to CSV file
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['Subdomain', 'Target', 'Status']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for result in results:
                writer.writerow({
                    'Subdomain': result['subdomain'],
                    'Target': result['target'],
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
