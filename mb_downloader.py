import requests
import pyzipper
import os
import argparse
import csv
import sys
import configparser
import zipfile
import concurrent.futures
from datetime import datetime, timedelta

def _worker_extract_chunk(zip_path, filenames_chunk, zip_password, allowed_extensions, target_dir, search_val):
    results = []
    try:
        with pyzipper.AESZipFile(zip_path, 'r', encryption=pyzipper.WZ_AES) as z:
            z.pwd = zip_password
            for filename in filenames_chunk:
                safe_filename = os.path.basename(filename)
                if not safe_filename:
                    continue
                    
                sha256_hash = safe_filename.split('.')[0]
                is_pe = False
                file_data = None
                
                try:
                    with z.open(filename) as f:
                        header = f.read(2)
                        if header == b'MZ':
                            is_pe = True
                            
                        if allowed_extensions:
                            pe_targets = ['exe', 'dll', 'sys', 'ocx', 'imphash', 'pe']
                            if any(ext in allowed_extensions for ext in pe_targets):
                                if not is_pe:
                                    continue
                                    
                        file_data = header + f.read()
                        
                    if file_data is not None:
                        save_name = f"{sha256_hash}.exe" if is_pe else safe_filename
                        new_path = os.path.join(target_dir, save_name)
                        
                        with open(new_path, 'wb') as out_file:
                            out_file.write(file_data)
                            
                        results.append({
                            'sha256_hash': sha256_hash,
                            'save_name': save_name,
                            'is_pe': is_pe,
                            'target_dir': target_dir,
                            'search_val': search_val
                        })
                except Exception as e:
                    print(f"[-] Error extracting {filename}: {e}")
    except Exception as e:
        print(f"[-] Error opening zip batch: {e}")
        
    return results

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
        if self.days:
            self.end_dt = datetime.now().replace(hour=23, minute=59, second=59)
            self.start_dt = (self.end_dt - timedelta(days=self.days)).replace(hour=0, minute=0, second=0)
        elif self.date_range:
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
        self.day_folder = os.path.join(self.output_dir, self.today_str)
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

    def _save_to_csv_bulk(self, rows_data):
        if not rows_data:
            return
        file_exists = os.path.exists(self.csv_log_file)
        with open(self.csv_log_file, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(['Date/Time', 'Search Value', 'Family (Signature)', 'SHA256 Hash', 'Saved File Path', 'File Type', 'YARA Rules'])
            writer.writerows(rows_data)

    def run_legacy(self, search_type, search_values, search_name):
        for val in search_values:
            target_dir = os.path.join(self.day_folder, val)
            if not os.path.exists(target_dir): 
                os.makedirs(target_dir)
            
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
            print("[-] ERROR: Advanced mode requires a --date, --days or --date-range to be set.")
            sys.exit(1)
            
        current_date = self.start_dt
        while current_date <= self.end_dt:
            date_str = current_date.strftime("%Y-%m-%d")
            print(f"\n[*] Processing Daily Batch: {date_str}")
            
            current_day_folder = os.path.join(self.output_dir, date_str)
            if not os.path.exists(current_day_folder):
                os.makedirs(current_day_folder)
            
            batch_url = f"https://datalake.abuse.ch/malware-bazaar/daily/{date_str}.zip"
            batch_zip_path = os.path.join(current_day_folder, f"batch_{date_str}.zip")
            
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
                print(f"[-] Download failed: {e}")
                current_date += timedelta(days=1)
                continue
            
            extracted_count = 0
            
            if os.path.exists(batch_zip_path):
                try:
                    with pyzipper.AESZipFile(batch_zip_path, 'r', encryption=pyzipper.WZ_AES) as z:
                        z.pwd = self.zip_password
                        full_file_list = z.namelist()
                    
                    tasks = []
                    for filename in full_file_list:
                        sha256 = os.path.basename(filename).split('.')[0]
                        if self.no_dupes and sha256 in self.downloaded_history:
                            continue
                        tasks.append(filename)
                        
                    total_tasks = len(tasks)
                    
                    if total_tasks > 0:
                        target_dir = os.path.join(current_day_folder, search_values[0])
                        if not os.path.exists(target_dir): 
                            os.makedirs(target_dir)
                            
                        cpu_count = os.cpu_count() or 4
                        print(f"[*] Firing up {cpu_count} CPU cores for parallel extraction...")
                        
                        chunk_size = 250
                        chunks = [tasks[i:i + chunk_size] for i in range(0, total_tasks, chunk_size)]
                        total_chunks = len(chunks)
                        
                        all_csv_rows = []

                        with concurrent.futures.ProcessPoolExecutor() as executor:
                            futures = {
                                executor.submit(
                                    _worker_extract_chunk, 
                                    batch_zip_path, 
                                    chunk, 
                                    self.zip_password, 
                                    self.allowed_extensions, 
                                    target_dir, 
                                    search_values[0]
                                ): chunk for chunk in chunks
                            }
                            
                            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                                percent = (i + 1) / total_chunks
                                bar_length = 40
                                filled_length = int(bar_length * percent)
                                bar = '█' * filled_length + '-' * (bar_length - filled_length)
                                sys.stdout.write(f'\r\033[92m[*] Parallelling Extraction: |{bar}| {percent:.1%} ({i+1}/{total_chunks} chunks)\033[0m')
                                sys.stdout.flush()
                                
                                res_list = future.result()
                                if res_list:
                                    for res in res_list:
                                        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        all_csv_rows.append([
                                            ts, 
                                            res['search_val'], 
                                            "Unknown", 
                                            res['sha256_hash'], 
                                            os.path.join(res['target_dir'], res['save_name']), 
                                            "PE_File" if res['is_pe'] else "Unknown", 
                                            "Batch Download"
                                        ])
                                        if self.no_dupes:
                                            self.downloaded_history.add(res['sha256_hash'])
                                    extracted_count += len(res_list)
                                    
                        print() 
                        
                        if all_csv_rows:
                            self._save_to_csv_bulk(all_csv_rows)
                            if self.no_dupes:
                                for row in all_csv_rows:
                                    self._save_history(row[3])
                                
                except zipfile.BadZipFile:
                     print("\n[-] ERROR: Downloaded massive batch is corrupted (BadZipFile). Skipping...")
                except Exception as e:
                     print(f"\n[-] ERROR during extraction process: {e}")
                     
                try:
                    os.remove(batch_zip_path)
                except Exception as e:
                    print(f"[-] Could not remove batch zip: {e}")
                    
            print(f"[+] Advanced extraction complete. Acquired {extracted_count} samples for {date_str}.")
            current_date += timedelta(days=1)

    def _extract_and_log(self, zip_path, target_dir, sha256_hash, search_val, signature, f_type, yara_str):
        try:
            with pyzipper.AESZipFile(zip_path, 'r', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as z:
                z.pwd = self.zip_password
                filenames = z.namelist()
                
                for filename in filenames:
                    safe_name = os.path.basename(filename)
                    if not safe_name: continue
                    source = z.open(filename)
                    target = open(os.path.join(target_dir, safe_name), "wb")
                    with source, target:
                        import shutil
                        shutil.copyfileobj(source, target)
                
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file_name = os.path.basename(filenames[0]) if filenames else sha256_hash
                self._save_to_csv([ts, search_val, signature, sha256_hash, os.path.join(target_dir, file_name), f_type, yara_str])
                
                if self.no_dupes:
                    self._save_history(sha256_hash)
                    self.downloaded_history.add(sha256_hash)
        except Exception as e:
            print(f"[-] Extract and log error for {sha256_hash}: {e}")
        finally:
            if os.path.exists(zip_path): 
                try:
                    os.remove(zip_path)
                except Exception:
                    pass

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
