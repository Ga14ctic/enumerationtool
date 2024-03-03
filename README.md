# EnumerationTool

EnumerationTool is an advanced penetration testing tool designed for comprehensive host enumeration. It leverages various techniques, including nmap scanning, vulnerability detection, and the retrieval of relevant CVE codes.

## Features

- **Host Enumeration:** Gather detailed information about the target host, including open ports, services, and potential vulnerabilities.
- **Nmap Scanning:** Perform in-depth nmap scans to identify vulnerabilities and potential attack vectors.
- **CVE Code Retrieval:** Find relevant Common Vulnerabilities and Exposures (CVE) codes for discovered vulnerabilities.

## Usage

```bash
python enum_tool.py (target)
```

## Flags

-h will initiate a help menu

## Installation

1. Clone the repository
```bash
git clone https://github.com/ga14ctic/enumerationtool
```
2. Install python dependencies
```bash
pip install -r requirements.txt
```
3. Install nmap and searchsploit
```bash
sudo apt-get install nmap | sudo apt-get install searchsploit
```

## Disclaimer

Please ensure that the usage of this tool is for legal and ethical purposes. Use responsibly and only on systems you have been given explicit permission to do so on.
