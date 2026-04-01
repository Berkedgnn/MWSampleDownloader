"""
imphash_scanner.py
------------------
Verilen dosya/dizin yollarının imphash değerlerini hesaplayıp
bir metin dosyasına yazar.

Kullanım:
    # Yolları komut satırından ver (az sayıda dosya için):
    python imphash_scanner.py "C:\\Windows\\System32\\notepad.exe" "C:\\Windows\\System32\\cmd.exe"

    # Yolları bir liste dosyasından oku (çok sayıda dosya için - ÖNERİLEN):
    python imphash_scanner.py --file dosya_listesi.txt

    # Liste dosyası + özel çıktı adı:
    python imphash_scanner.py --file dosya_listesi.txt -o sonuclar.txt

Gereksinimler:
    pip install pefile
"""

import os
import sys
import argparse
import datetime

try:
    import pefile
except ImportError:
    print("[HATA] 'pefile' modülü bulunamadı. Yüklemek için:\n  pip install pefile")
    sys.exit(1)


# Taranacak dosya uzantıları (dizin tarama modunda kullanılır)
PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".drv", ".cpl"}


def get_imphash(filepath: str) -> str:
    """Verilen PE dosyasının imphash değerini döndürür."""
    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        imphash = pe.get_imphash()
        pe.close()
        return imphash if imphash else "N/A (import tablosu yok)"
    except pefile.PEFormatError:
        return "HATA: Geçerli bir PE dosyası değil"
    except PermissionError:
        return "HATA: Erişim izni reddedildi"
    except Exception as e:
        return f"HATA: {e}"


def scan_path(path: str, recursive: bool = True):
    """
    Verilen yol bir dosyaysa doğrudan imphash hesaplar,
    dizinse içindeki PE dosyalarını tarar.
    Yields: (filepath, imphash)
    """
    path = path.strip()
    if not path:
        return

    if os.path.isfile(path):
        yield path, get_imphash(path)

    elif os.path.isdir(path):
        walker = os.walk(path) if recursive else [(path, [], os.listdir(path))]
        for root, _, files in walker:
            for filename in files:
                ext = os.path.splitext(filename)[1].lower()
                if ext in PE_EXTENSIONS:
                    filepath = os.path.join(root, filename)
                    yield filepath, get_imphash(filepath)
    else:
        print(f"[UYARI] Yol bulunamadı, atlanıyor: {path}")


def load_paths_from_file(list_file: str) -> list:
    """
    Satır satır yol içeren bir .txt dosyasını okur.
    Boş satırları ve # ile başlayan yorum satırlarını atlar.
    """
    if not os.path.isfile(list_file):
        print(f"[HATA] Liste dosyası bulunamadı: {list_file}")
        sys.exit(1)

    paths = []
    with open(list_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                paths.append(line)
    return paths


def main():
    parser = argparse.ArgumentParser(
        description="PE dosyalarının imphash değerlerini hesaplar ve dosyaya yazar.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "paths",
        nargs="*",
        metavar="YOL",
        help="Dosya veya dizin yolları (isteğe bağlı, --file ile birlikte kullanılabilir)",
    )
    parser.add_argument(
        "-f", "--file",
        metavar="LISTE_DOSYASI",
        help=(
            "Her satırda bir yol içeren metin dosyası.\n"
            "Boş satırlar ve # ile başlayan satırlar yoksayılır.\n"
            "Örnek dosya içeriği:\n"
            "  C:\\Windows\\System32\\LbfoAdmin.exe\n"
            "  C:\\Windows\\System32\\notepad.exe\n"
            "  # Bu bir yorum satırıdır\n"
            "  C:\\Windows\\SysWOW64\\cmd.exe"
        ),
    )
    parser.add_argument(
        "-o", "--output",
        default="imphash_results.txt",
        metavar="DOSYA",
        help="Çıktı dosyası adı (varsayılan: imphash_results.txt)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Dizin taramada alt klasörlere girme",
    )
    parser.add_argument(
        "--extensions",
        nargs="+",
        metavar="UZT",
        help="Dizin taramada kullanılacak uzantılar (örn: .exe .dll)",
    )
    args = parser.parse_args()

    # En az bir yol kaynağı olmalı
    if not args.paths and not args.file:
        parser.print_help()
        sys.exit(1)

    # Özel uzantı listesi
    global PE_EXTENSIONS
    if args.extensions:
        PE_EXTENSIONS = {ext if ext.startswith(".") else f".{ext}" for ext in args.extensions}

    # Tüm yolları bir araya getir
    all_paths = list(args.paths)
    if args.file:
        file_paths = load_paths_from_file(args.file)
        print(f"[*] Liste dosyasından {len(file_paths)} yol okundu: {args.file}")
        all_paths.extend(file_paths)

    recursive = not args.no_recursive
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = 0
    errors = 0

    with open(args.output, "w", encoding="utf-8") as out:
        out.write("=" * 100 + "\n")
        out.write("  IMPHASH TARAMA RAPORU\n")
        out.write(f"  Tarih/Saat       : {timestamp}\n")
        out.write(f"  Toplam yol sayısı: {len(all_paths)}\n")
        out.write(f"  Kaynak           : {'--file: ' + args.file if args.file else 'Komut satırı'}\n")
        out.write("=" * 100 + "\n\n")
        out.write(f"{'DOSYA YOLU':<80}  {'IMPHASH'}\n")
        out.write("-" * 120 + "\n")

        for path in all_paths:
            for filepath, imphash in scan_path(path, recursive):
                line = f"{filepath:<80}  {imphash}\n"
                out.write(line)
                print(line, end="")
                total += 1
                if imphash.startswith("HATA"):
                    errors += 1

        out.write("\n" + "-" * 120 + "\n")
        out.write(f"Toplam işlenen dosya : {total}\n")
        out.write(f"Başarılı             : {total - errors}\n")
        out.write(f"Hatalı               : {errors}\n")

    print(f"\n[✓] Tamamlandı! {total} dosya işlendi.")
    print(f"[✓] Sonuçlar '{args.output}' dosyasına yazıldı.")


if __name__ == "__main__":
    main()
