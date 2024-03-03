import argparse
import subprocess
import shlex
import re

def nmap_scan(target):
    try:
        result = subprocess.run(['nmap', '-sV', '--script', 'vulners', target], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error during nmap scan: {e}")
        return None

def searchsploit_cve(cve):
    try:
        result = subprocess.run(['searchsploit', cve], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error during searchsploit lookup: {e}")
        return None

def extract_cve(output):
    # Extract CVE codes from the nmap scan output
    cve_pattern = re.compile(r'(CVE-\d{4}-\d{4,7})')
    cve_matches = cve_pattern.findall(output)
    return cve_matches

def main():
    parser = argparse.ArgumentParser(description="Enumeration Tool for Penetration Testing")
    parser.add_argument('-t', '--target', help='Target IP or domain', required=True)
    args = parser.parse_args()

    target = args.target

    print(f"Scanning target: {target}")

    # Perform nmap scan to identify potential vulnerabilities
    nmap_output = nmap_scan(target)

    if nmap_output:
        print("Nmap Scan Results:")
        print(nmap_output)

        # Extract CVE codes from nmap scan output
        cve_codes = extract_cve(nmap_output)

        if cve_codes:
            print("\nPotential Vulnerabilities:")
            for cve_code in cve_codes:
                print(f" - {cve_code}")

                # Search for the CVE code using searchsploit
                searchsploit_result = searchsploit_cve(cve_code)

                if searchsploit_result:
                    print("   Searchsploit Results:")
                    print(searchsploit_result)
                else:
                    print("   No relevant CVE code found in searchsploit.")
        else:
            print("No potential vulnerabilities found.")
    else:
        print("Error: Nmap scan failed.")

if __name__ == "__main__":
    main()
