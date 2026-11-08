# ssl-cipher-strength-checker

Classify TLS cipher suites from a CSV as STRONG, WEAK, INSECURE or UNKNOWN: modern AEAD suites are strong, NULL/EXPORT/anonymous/DES are insecure, 3DES/RC4/MD5 are weak — insecure first.

## How to run

```sh
python3 main.py ciphers.csv
```

## Example output

```
TLS_RSA_WITH_DES_CBC_SHA (TLSv1.2): INSECURE
TLS_RSA_WITH_RC4_128_SHA (TLSv1.2): WEAK
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLSv1.2): STRONG
1 insecure, 1 weak, 0 unknown, 1 strong.
```

Standard library only. Run the tests with `python3 -m unittest discover`.
