import requests
import pyzipper
import os
import argparse
import csv
import sys
import configparser
import zipfile
from datetime import datetime, timedelta

class MalwareDownloader:
    def __init__(self, api_key, output_dir, mode='legacy', limit=50, days=None, exact_date=None, date_range=None, no_dupes=False, extensions=None):
        self.api_url = "https://mb-api.abuse.ch/api/v1/"
        self.zip_password = b"infected"
        self.headers = {'Auth-Key': api_key}
        
        self.output_dir = output_dir
        self.mode = mode
        self.limit = limit
        self.days = days
        self.exact_date = exact_date
        self.date_range = date_range
        self.no_dupes = no_dupes
        
        # Uzantıları ayarla ve "imphash/pe" kısayolunu akıllıca genişlet
        if extensions:
            self.allowed_extensions = [ext.strip().lower() for ext in extensions.split(",")]
            if "imphash" in self.allowed_extensions or "pe" in self.allowed_extensions:
                self.allowed_extensions.extend(["exe", "dll", "sys", "ocx"])
        else:
            self.allowed_extensions = None
        
        self.start_dt = None
        self.end_dt = None
        self._parse_dates()
            
        self.today_str = datetime.now().strftime("%Y-%m-%d")
        self._setup_directories()
        
        self.history_file = os.path.join(self.output_dir, "downloaded_hashes.txt")
        self.csv_log_file = os.path.join(self.day_folder, f"download_log_{self.today_str}.csv")
        
        self.downloaded_history = set()
        if self.no_dupes:
            self._load_history()

    def _parse_dates(self):
        if self.date_range:
            try:
                start_str, end_str = self.date_range.split(":")
                self.start_dt = datetime.strptime(start_str.strip(), "%Y-%m-%d")
                self.end_dt = datetime.strptime(end_str.strip(), "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            except ValueError:
                print("[-] ERROR: Invalid date range format. Use YYYY-MM-DD:YYYY-MM-DD")
                sys.exit(1)
        elif self.exact_date:
            self.start_dt = datetime.strptime(self.exact_date, "%Y-%m-%d")
            self.end_dt = self.start_dt.replace(hour=23, minute=59, second=59)

    def _setup_directories(self):
        if not os.path.exists(self.output_dir): 
            os.makedirs(self.output_dir)
        self.day_folder = os.path.join(self.output_dir, f"download_date_{self.today_str}")
        if not os.path.exists(self.day_folder): 
            os.makedirs(self.day_folder)

    def _load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file, 'r') as f:
                self.downloaded_history = set(line.strip() for line in f if line.strip())

    def _save_history(self, sha256_hash):
        with open(self.history_file, 'a') as f: 
            f.write(f"{sha256_hash}\n")

    def _save_to_csv(self, row_data):
        file_exists = os.path.exists(self.csv_log_file)
        with open(self.csv_log_file, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['Date/Time', 'Search Value', 'Family (Signature)', 'SHA256 Hash', 'Saved File Path', 'File Type', 'YARA Rules'])
            writer.writerow(row_data)

    def run_legacy(self, search_type, search_values, search_name):
        for val in search_values:
            data = {'query': search_type, 'limit': self.limit}
            if search_type == 'get_taginfo': 
                data['tag'] = val
            elif search_type == 'get_siginfo': 
                data['signature'] = val
                
            response = requests.post(self.api_url, data=data, headers=self.headers)
            if response.status_code == 200 and response.json().get('query_status') == 'ok':
                samples = response.json().get('data', [])
                
                for entry in samples:
                    h = entry['sha256_hash']
                    sig = entry.get('signature', 'Unknown')
                    f_type = entry.get('file_type', 'Unknown').lower()
                    
                    first_seen = entry.get('first_seen', '')
                    malware_date = first_seen.split(' ')[0] if first_seen else 'Unknown_Date'
                    folder_prefix = f"malware_date_{malware_date}" if malware_date != 'Unknown_Date' else 'Unknown_Date'
                    
                    target_dir = os.path.join(self.day_folder, folder_prefix, val)
                    if not os.path.exists(target_dir): 
                        os.makedirs(target_dir)
                    
                    if self.allowed_extensions and f_type not in self.allowed_extensions:
                        continue
                    
                    if self.no_dupes and h in self.downloaded_history:
                        continue
                    
                    self._download_single_file(h, target_dir, val, sig, f_type, "N/A")

    def _download_single_file(self, sha256_hash, target_dir, search_val, signature, f_type, yara_str):
        data = {'query': 'get_file', 'sha256_hash': sha256_hash}
        res = requests.post(self.api_url, data=data, headers=self.headers)
        if res.status_code == 200 and b'"query_status"' not in res.content[:50]:
            zip_path = os.path.join(target_dir, f"{sha256_hash}.zip")
            with open(zip_path, 'wb') as f: 
                f.write(res.content)
            self._extract_and_log(zip_path, target_dir, sha256_hash, search_val, signature, f_type, yara_str)

    def run_advanced(self, search_values, search_name):
        if not self.start_dt:
            print("[-] ERROR: Advanced mode requires a --date or --date-range to be set.")
            sys.exit(1)
            
        current_date = self.start_dt
        while current_date <= self.end_dt:
            date_str = current_date.strftime("%Y-%m-%d")
            
            malware_date_folder = os.path.join(self.day_folder, f"malware_date_{date_str}")
            if not os.path.exists(malware_date_folder):
                os.makedirs(malware_date_folder)
                
            print(f"\n[*] Processing Daily Batch: {date_str}")
            
            # --- TEK GERÇEK VE ÇALIŞAN LİNK ---
            batch_url = f"https://mb-api.abuse.ch/downloads/{date_str}.zip"
            batch_zip_path = os.path.join(malware_date_folder, f"batch_{date_str}.zip")
            
            print(f"[*] Downloading massive payload batch from {batch_url} ...")
            try:
                with requests.get(batch_url, stream=True) as r:
                    content_type = r.headers.get('Content-Type', '')
                    
                    if r.status_code != 200 or 'zip' not in content_type.lower():
                        print(f"[-] No valid zip batch found for {date_str}. Server returned a non-zip response.")
                        current_date += timedelta(days=1)
                        continue
                        
                    total_size_in_bytes = int(r.headers.get('content-length', 0))
                    downloaded_size = 0
                        
                    with open(batch_zip_path, 'wb') as f:
                        for chunk in r.iter_content(chunk_size=8192): 
                            if chunk:
                                f.write(chunk)
                                downloaded_size += len(chunk)
                                
                    if total_size_in_bytes != 0 and downloaded_size < total_size_in_bytes:
                        print(f"[-] ERROR: Download incomplete. Expected {total_size_in_bytes} bytes, got {downloaded_size} bytes.")
                        os.remove(batch_zip_path)
                        current_date += timedelta(days=1)
                        continue
                        
            except Exception as e:
                err_str = str(e)
                # DNS VE FIREWALL HATALARINI ÖZEL OLARAK YAKALAMA
                if "getaddrinfo" in err_str or "NameResolution" in err_str:
                    print(f"[-] DNS/FIREWALL ERROR: Sanal makinen (TestVM) datalake.abuse.ch adresini çözemedi!")
                    print(f"    Lütfen VM'in DNS ayarlarini (örn: 8.8.8.8) veya Firewall engellerini kontrol et.")
                else:
                    print(f"[-] Download failed: {e}")
                current_date += timedelta(days=1)
                continue
            
            extracted_count = 0
            
            if os.path.exists(batch_zip_path):
                try:
                    with pyzipper.AESZipFile(batch_zip_path, 'r', encryption=pyzipper.WZ_AES) as z:
                        z.pwd = self.zip_password
                        
                        file_list = z.namelist()
                        total_files = len(file_list)
                        
                        for i, filename in enumerate(file_list):
                            # --- YESIL PROGRESS BAR ---
                            percent = (i + 1) / total_files
                            bar_length = 40
                            filled_length = int(bar_length * percent)
                            bar = '█' * filled_length + '-' * (bar_length - filled_length)
                            sys.stdout.write(f'\r\033[92m[*] Analyzing Magic Bytes: |{bar}| {percent:.1%} ({i+1}/{total_files})\033[0m')
                            sys.stdout.flush()
                            # --------------------------

                            sha256_hash = filename.split('.')[0]
                            
                            if self.no_dupes and sha256_hash in self.downloaded_history:
                                continue
                                
                            is_pe = False
                            try:
                                with z.open(filename) as f:
                                    header = f.read(2)
                                    if header == b'MZ':
                                        is_pe = True
                            except Exception:
                                pass
                                
                            if self.allowed_extensions:
                                pe_targets = ['exe', 'dll', 'sys', 'ocx', 'imphash', 'pe']
                                if any(ext in self.allowed_extensions for ext in pe_targets):
                                    if not is_pe:
                                        continue
                                        
                            target_dir = os.path.join(malware_date_folder, search_values[0])
                            if not os.path.exists(target_dir): 
                                os.makedirs(target_dir)
                            
                            save_name = f"{sha256_hash}.exe" if is_pe else filename
                            
                            try:
                                z.extract(filename, path=target_dir)
                                old_path = os.path.join(target_dir, filename)
                                new_path = os.path.join(target_dir, save_name)
                                
                                if old_path != new_path and os.path.exists(old_path):
                                    os.rename(old_path, new_path)
                                    
                                self._log_advanced(sha256_hash, target_dir, save_name, [search_values[0], "Unknown", "PE_File" if is_pe else "Unknown"])
                                extracted_count += 1
                            except Exception:
                                pass
                        
                        print() 
                                
                except zipfile.BadZipFile:
                     print("\n[-] ERROR: Downloaded massive batch is corrupted (BadZipFile). Skipping...")
                     
                try:
                    os.remove(batch_zip_path)
                except Exception:
                    pass
                    
            print(f"[+] Advanced extraction complete. Acquired {extracted_count} samples for {date_str}.")
            current_date += timedelta(days=1)

    def _extract_and_log(self, zip_path, target_dir, sha256_hash, search_val, signature, f_type, yara_str):
        try:
            with pyzipper.AESZipFile(zip_path, 'r', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
                z.pwd = self.zip_password
                filenames = z.namelist()
                z.extractall(path=target_dir)
                
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file_name = filenames[0] if filenames else sha256_hash
                self._save_to_csv([ts, search_val, signature, sha256_hash, os.path.join(target_dir, file_name), f_type, yara_str])
                
                if self.no_dupes:
                    self._save_history(sha256_hash)
                    self.downloaded_history.add(sha256_hash)
        except Exception:
            pass
        finally:
            if os.path.exists(zip_path): 
                os.remove(zip_path)
            
    def _log_advanced(self, sha256_hash, target_dir, filename, meta):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._save_to_csv([ts, meta[0], meta[1], sha256_hash, os.path.join(target_dir, filename), meta[2], "Batch Download"])
        if self.no_dupes:
            self._save_history(sha256_hash)
            self.downloaded_history.add(sha256_hash)

def get_api_key(args_api_key):
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
            print("[-] API Key missing. Check mb_config.conf")
            sys.exit(1)
    return api_key

def main():
    parser = argparse.ArgumentParser(description="MalwareBazaar Downloader")
    
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-t", "--tag", type=str)
    group.add_argument("-s", "--sig", type=str)
    
    parser.add_argument("-o", "--output", type=str, required=True)
    parser.add_argument("-m", "--mode", choices=['legacy', 'advanced'], default='legacy')
    parser.add_argument("-k", "--api-key", type=str)
    parser.add_argument("-l", "--limit", type=int, default=100)
    parser.add_argument("-e", "--ext", type=str, help="e.g. 'exe,dll' or 'imphash' to grab all PE files")
    
    date_group = parser.add_mutually_exclusive_group()
    date_group.add_argument("-d", "--days", type=int)
    date_group.add_argument("--date", type=str)
    date_group.add_argument("--date-range", type=str)
    
    parser.add_argument("--no-dupes", action="store_true")
    args = parser.parse_args()
    
    if not args.tag and not args.sig:
        if args.mode == 'legacy':
            print("[-] ERROR: Legacy mode requires a -t (tag) or -s (sig) parameter.")
            sys.exit(1)
        stype, svals, sname = ('all', ['All_Samples'], 'ALL')
    else:
        if args.sig:
            stype, svals, sname = 'get_siginfo', [v.strip() for v in args.sig.split(",")], "SIGNATURE"
        else:
            stype, svals, sname = 'get_taginfo', [v.strip() for v in args.tag.split(",")], "TAG"
            
    api_key = get_api_key(args.api_key)
    
    downloader = MalwareDownloader(
        api_key=api_key,
        output_dir=args.output,
        mode=args.mode,
        limit=args.limit,
        days=args.days,
        exact_date=args.date,
        date_range=args.date_range,
        no_dupes=args.no_dupes,
        extensions=args.ext
    )
    
    if input("Start download? (Y/N): ").lower() != 'y': 
        sys.exit(0)
    
    if args.mode == 'legacy':
        downloader.run_legacy(stype, svals, sname)
    elif args.mode == 'advanced':
        downloader.run_advanced(svals, sname)

if __name__ == "__main__":
    main()
