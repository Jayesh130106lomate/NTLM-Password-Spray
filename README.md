# NTLM Password Spray Tool

A Python-based NTLM authentication brute force tool for penetration testing and security assessments.

## Features

- Password spray attacks against NTLM authentication
- Configurable delays to avoid account lockouts
- Error handling for timeouts and connection issues
- Colored output for better visibility
- Export results to file
- Verbose mode for detailed logging

## Installation

```bash
pip install requests requests-ntlm
```

## Usage

Basic usage:
```bash
python NTLM_brut.py -u userlist.txt -p Password123 -t http://target.com -d DOMAIN
```

With delay and output file:
```bash
python NTLM_brut.py -u userlist.txt -p Password123 -t http://target.com -d DOMAIN --delay 2 -o results.txt
```

### Arguments

- `-u, --userlist`: File containing usernames (one per line)
- `-p, --password`: Password to spray
- `-t, --target`: Target URL
- `-d, --domain`: Domain/FQDN
- `-v, --verbose`: Enable verbose output
- `--delay`: Delay between requests in seconds (default: 0)
- `--timeout`: Request timeout in seconds (default: 10)
- `-o, --output`: Output file to save valid credentials

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal.
