"""Classify TLS cipher suites as STRONG, WEAK, INSECURE or UNKNOWN.

Usage: python3 main.py ciphers.csv
CSV columns: cipher,protocol.
STRONG: modern AEAD suites (AES-GCM, AES-CCM, CHACHA20).
INSECURE: NULL, EXPORT, anonymous key exchange, or plain DES.
WEAK: 3DES, RC4, MD5, or anything else recognised but outdated.
UNKNOWN: anything that matches none of the above rules.
INSECURE first, then WEAK, then UNKNOWN, then STRONG.
"""
import argparse, csv, sys

def classify(cipher):
    name = cipher.upper()
    if "NULL" in name or "EXPORT" in name or "ANON" in name or "ADH" in name or "AECDH" in name:
        return "INSECURE"
    if "DES" in name and "3DES" not in name and "DES_EDE" not in name:
        return "INSECURE"
    if "AES" in name and ("GCM" in name or "CCM" in name):
        return "STRONG"
    if "CHACHA20" in name:
        return "STRONG"
    if "3DES" in name or "DES_EDE" in name or "RC4" in name or "MD5" in name:
        return "WEAK"
    if "AES" in name or "CAMELLIA" in name or "ARIA" in name:
        return "WEAK"
    return "UNKNOWN"

def check(rows):
    out = []
    for row in rows:
        out.append((row["cipher"].strip(), row["protocol"].strip(), classify(row["cipher"])))
    order = {"INSECURE": 0, "WEAK": 1, "UNKNOWN": 2, "STRONG": 3}
    return sorted(out, key=lambda r: (order[r[2]], r[0]))

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path")
    args = parser.parse_args(argv)
    with open(args.path, newline="", encoding="utf-8") as f:
        results = check(list(csv.DictReader(f)))
    for cipher, protocol, verdict in results:
        print(f"{cipher} ({protocol}): {verdict}")
    print(f"{sum(1 for *_, v in results if v == 'INSECURE')} insecure, "
          f"{sum(1 for *_, v in results if v == 'WEAK')} weak, "
          f"{sum(1 for *_, v in results if v == 'UNKNOWN')} unknown, "
          f"{sum(1 for *_, v in results if v == 'STRONG')} strong.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
