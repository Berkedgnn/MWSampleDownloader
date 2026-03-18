import requests
import pyzipper
import os
import argparse
import csv
import sys
import configparser
from datetime import datetime

class MalwareDownloader:
    """Main class managing malware download operations via MalwareBazaar API."""
    
    def __init__(self, api_key, output_dir, limit=50, days=None, exact_date=None, no_dupes=False):
        # Base Configurations
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        self.zip_password = b"infected"
        self.headers = {'Auth-Key': api_key}
        
        # User Parameters
        self.output_dir = output_dir
        self.limit = limit
        self.days = days
        self.exact_date = exact_date
        self.no_dupes = no_dupes
        
        # Directory and File Paths
        self.today_str = datetime.now().strftime("%Y-%m-%d")
        self._setup_directories()
        
        self.history_file = os.path.join(self.output_dir, "downloaded_hashes.txt")
        self.csv_log_file = os.path.join(self.day_folder, f"download_log_{self.today_str}.csv")
        
        # History Management
        self.downloaded_history = set()
        if self.no_dupes:
            self._load_history()

    def _setup_directories(self):
        """Creates output directories and today's subfolder."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        self.day_folder = os.path.join(self.output_dir, self.today_str)
        if not os.path.exists(self.day_folder):
            os.makedirs(self.day_folder)

    def _load_history(self):
        """Loads previously downloaded hashes into memory."""
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                self.downloaded_history = set(line.strip() for line in f if line.strip())
        print(f"[*] Duplicate prevention active. {len(self.downloaded_history)} hashes found in the database.")

    def _save_history(self, sha256_hash):
        """Saves newly downloaded hash to the history file."""
        with open(self.history_file, 'a') as f:
            f.write(f"{sha256_hash}\n")

    def _save_to_csv(self, row_data):
        """Saves download details to the CSV file."""
        file_exists = os.path.exists(self.csv_log_file)
        
        with open(self.csv_log_file, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['Date/Time', 'Search Value', 'SHA256 Hash', 'Saved File Path', 'File Type', 'YARA Rules'])
            writer.writerow(row_data)

    def get_samples(self, search_type, search_value):
        """Fetches malware list matching the criteria from the API."""
        data = {'query': search_type, 'limit': self.limit}
        
        if search_type == 'get_taginfo':
            data['tag'] = search_value
        elif search_type == 'get_siginfo':
            data['signature'] = search_value
            
        response = requests.post(self.api_url, data=data, headers=self.headers)
        valid_samples = []
        
        if response.status_code == 200:
            json_data = response.json()
            if json_data.get('query_status') == 'ok':
                now = datetime.now()
                
                for entry in json_data.get('data', []):
                    sha256 = entry['sha256_hash']
                    first_seen_str = entry.get('first_seen')
                    
                    if first_seen_str:
                        try:
                            first_seen_date = datetime.strptime(first_seen_str, "%Y-%m-%d %H:%M:%S")
                            
                            # Filter 1: Number of Days (-d / --days)
                            if self.days is not None:
                                if (now - first_seen_date).days > self.days:
                                    continue 
                                    
                            # Filter 2: Exact Date (--date)
                            if self.exact_date is not None:
                                sample_date_only = first_seen_date.strftime("%Y-%m-%d")
                                if sample_date_only != self.exact_date:
                                    continue
                                    
                        except ValueError:
                            pass 
                    
                    file_type = entry.get('file_type', 'Unknown')
                    yara_data = entry.get('yara_rules')
                    yara_rules = [y.get('rule_name', 'Unknown Rule') for y in yara_data] if yara_data else []
                    
                    valid_samples.append({
                        'hash': sha256,
                        'type': file_type,
                        'yara': yara_rules
                    })
        return valid_samples

    def download_and_extract(self, sha256_hash, target_dir):
        """Downloads the file and extracts it from the ZIP."""
        data = {'query': 'get_file', 'sha256_hash': sha256_hash}
        response = requests.post(self.api_url, data=data, headers=self.headers)
        extracted_files = []
        
        if response.status_code == 200 and response.content:
            if b'"query_status"' in response.content[:50]: 
                print(f"  [-] API Error/Limit reached or File Not Found: {sha256_hash}")
                return False, []
                
            zip_path = os.path.join(target_dir, f"{sha256_hash}.zip")
            with open(zip_path, 'wb') as f:
                f.write(response.content)
                
            try:
                with pyzipper.AESZipFile(zip_path, 'r', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as extracted_zip:
                    extracted_zip.pwd = self.zip_password
                    extracted_files = extracted_zip.namelist()
                    extracted_zip.extractall(path=target_dir)
                    print(f"  [+] Downloaded and extracted: {sha256_hash}")
                    
                os.remove(zip_path) 
                return True, extracted_files
            except Exception as e:
                print(f"  [-] Extraction failed ({sha256_hash}): {e}")
                if os.path.exists(zip_path):
                    os.remove(zip_path)
                return False, []
        else:
            print(f"  [-] Download failed: {sha256_hash}")
            return False, []

    def run(self, search_type, search_values, search_name):
        """Main function to start the download operation."""
        print(f"[*] Main Output Directory: {self.output_dir}")
        print("="*55)

        for val in search_values:
            print(f"\n[*] {search_name}: Searching for '{val}'...")
            
            target_dir = os.path.join(self.day_folder, val)
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
                
            sample_list = self.get_samples(search_type, val)
            
            if not sample_list:
                print(f"[-] No results found for '{val}' matching your criteria.")
                continue
                
            print(f"[+] Found {len(sample_list)} samples. Starting download...")
            
            for sample in sample_list:
                h = sample['hash']
                f_type = sample['type']
                yara_hits = sample['yara']
                yara_str = ", ".join(yara_hits) if yara_hits else "None"
                
                if self.no_dupes and h in self.downloaded_history:
                    print(f"  [*] Skipping (Already downloaded): {h}")
                    continue
                    
                success, extracted_filenames = self.download_and_extract(h, target_dir)
                
                if success:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    file_names_str = ", ".join(extracted_filenames) if extracted_filenames else h
                    full_saved_path = os.path.join(target_dir, file_names_str)
                    
                    self._save_to_csv([timestamp, val, h, full_saved_path, f_type, yara_str])
                    
                    if self.no_dupes:
                        self._save_history(h)
                        self.downloaded_history.add(h)

        print("\n" + "="*55)
        print("[+] All operations completed successfully.")
        print(f"[*] Detailed download log saved to: {self.csv_log_file}")


def get_user_confirmation():
    """Gets explicit user confirmation (Y/N) to proceed with the download."""
    print("\n" + "!"*60)
    print("[!] WARNING: YOU ARE DOWNLOADING REAL AND LIVE MALWARE!")
    print("[!] Please DO NOT EXECUTE these files on your host machine.")
    print("[!] Be extremely careful against accidental clicks.")
    print("!"*60)
    
    while True:
        choice = input("\nDo you want to proceed and start the download? (Y/N): ").strip().lower()
        if choice == 'y':
            return True
        elif choice == 'n':
            return False
        else:
            print("[-] Please enter only 'Y' (Yes) or 'N' (No).")


def get_api_key(args_api_key):
    """Retrieves API key from args, env var, or config file. Creates template if missing."""
    config_file = "mb_config.conf"
    api_key = args_api_key or os.getenv("MB_API_KEY")
    
    if not api_key:
        config = configparser.ConfigParser()
        if os.path.exists(config_file):
            config.read(config_file)
            if 'SETTINGS' in config and 'API_KEY' in config['SETTINGS']:
                api_key = config['SETTINGS']['API_KEY']
                
        if not api_key or api_key == "YOUR_API_KEY_HERE":
            if not os.path.exists(config_file):
                config['SETTINGS'] = {'API_KEY': 'YOUR_API_KEY_HERE'}
                with open(config_file, 'w') as f:
                    config.write(f)
                print(f"\n[-] ERROR: API Key is missing!")
                print(f"[-] A default config file '{config_file}' has been created in the current directory.")
                print("[-] Please edit this file and paste your MalwareBazaar API key.")
            else:
                print(f"\n[-] ERROR: API Key is missing or invalid in '{config_file}'!")
                print("[-] Please edit the file or provide the key via -k parameter.")
                
            print("[-] You can get a free key from: https://bazaar.abuse.ch/api/")
            sys.exit(1)
            
    return api_key


def main():
    parser = argparse.ArgumentParser(description="MalwareBazaar Advanced Downloader (OOP)")
    
    # Search Type Group (Must choose one)
    search_group = parser.add_mutually_exclusive_group(required=True)
    search_group.add_argument("-t", "--tag", type=str, help="Search by tag (e.g., ransomware)")
    search_group.add_argument("-s", "--sig", type=str, help="Search by signature (e.g., LummaStealer)")
    
    parser.add_argument("-o", "--output", type=str, required=True, help="Main output directory (REQUIRED)")
    parser.add_argument("-k", "--api-key", type=str, help="MalwareBazaar API Key (Optional if mb_config.conf is used)")
    parser.add_argument("-l", "--limit", type=int, default=50, help="Maximum number of samples to fetch from API (Default: 50)")
    
    # Date Filter Group (Must choose zero or one, cannot choose both)
    date_group = parser.add_mutually_exclusive_group()
    date_group.add_argument("-d", "--days", type=int, help="Only download samples from the last X days")
    date_group.add_argument("--date", type=str, help="Download samples from an exact date (Format: YYYY-MM-DD)")
    
    parser.add_argument("--no-dupes", action="store_true", help="Skip previously downloaded files (Prevent Duplicate)")

    args = parser.parse_args()

    # Validate exact date format if provided
    if args.date:
        try:
            datetime.strptime(args.date, "%Y-%m-%d")
        except ValueError:
            print("[-] ERROR: Incorrect date format. Please use YYYY-MM-DD (e.g., 2026-03-15).")
            sys.exit(1)

    api_key = get_api_key(args.api_key)

    if not get_user_confirmation():
        print("\n[*] Operation cancelled by user. Stay safe!")
        sys.exit(0)
        
    print("\n[*] Confirmation received. Starting the download process...\n")

    if args.sig:
        search_type, search_values, search_name = 'get_siginfo', [v.strip() for v in args.sig.split(",") if v.strip()], "SIGNATURE"
    else:
        search_type, search_values, search_name = 'get_taginfo', [v.strip() for v in args.tag.split(",") if v.strip()], "TAG"

    downloader = MalwareDownloader(
        api_key=api_key,
        output_dir=args.output,
        limit=args.limit,
        days=args.days,
        exact_date=args.date,
        no_dupes=args.no_dupes
    )
    
    downloader.run(search_type, search_values, search_name)

if __name__ == "__main__":
    main()
