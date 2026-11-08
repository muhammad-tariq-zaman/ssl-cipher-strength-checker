import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unittest
from main import classify, check

def row(c, p="TLSv1.2"):
    return {"cipher": c, "protocol": p}

class TestCipherStrength(unittest.TestCase):
    def test_aes_gcm_strong(self):
        self.assertEqual(classify("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"), "STRONG")
    def test_chacha20_strong(self):
        self.assertEqual(classify("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"), "STRONG")
    def test_rc4_weak(self):
        self.assertEqual(classify("TLS_RSA_WITH_RC4_128_SHA"), "WEAK")
    def test_3des_weak_not_insecure(self):
        self.assertEqual(classify("TLS_RSA_WITH_3DES_EDE_CBC_SHA"), "WEAK")
    def test_plain_des_insecure(self):
        self.assertEqual(classify("TLS_RSA_WITH_DES_CBC_SHA"), "INSECURE")
    def test_null_insecure(self):
        self.assertEqual(classify("TLS_RSA_WITH_NULL_MD5"), "INSECURE")
    def test_unknown_cipher(self):
        self.assertEqual(classify("TLS_FOO_WITH_BAR_BAZ"), "UNKNOWN")
    def test_insecure_first(self):
        r = check([row("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"), row("TLS_RSA_WITH_DES_CBC_SHA")])
        self.assertEqual(r[0][2], "INSECURE")
