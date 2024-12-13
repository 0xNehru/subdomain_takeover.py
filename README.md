# Subdomain Takeover Checker

# Author: 0xNehru

# Description:
This Python script is designed to identify potential subdomain takeover vulnerabilities by analyzing CNAME records of subdomains. With the growing complexity of modern web infrastructures, subdomain takeovers are a critical security risk often caused by misconfigured DNS settings or unclaimed cloud resources.

# Features:

    Resolves subdomain CNAME records using dns.resolver.
    Matches resolved targets against a comprehensive list of known takeover patterns (e.g., s3.amazonaws.com, github.io, etc.).
    Provides detailed results, categorizing each subdomain as vulnerable or safe.
    Outputs findings to a CSV file for easy reporting and analysis.

# How It Works:

    Reads a list of subdomains from an input file (urls.txt).
    Resolves the CNAME record for each subdomain.
    Checks the resolved CNAME against a predefined list of patterns associated with takeover vulnerabilities.
    Outputs the results, including the resolved target and vulnerability status, to a CSV file (results.csv).

# Use Cases:

    Security researchers auditing DNS configurations.
    Organizations testing their web infrastructure for potential vulnerabilities.
    Bug bounty hunters identifying takeover opportunities.

# How to Run:

    Install required dependencies:

pip install dnspython

Prepare a text file (urls.txt) containing a list of subdomains to check.
# Run the script:

    python subdomain_takeover.py

    View the results in results.csv.

# Disclaimer:
This script only identifies potential vulnerabilities. To confirm a subdomain takeover, further manual validation (e.g., claiming the resource) is required.
