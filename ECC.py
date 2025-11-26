import time
import sys
import random
import os

sys.setrecursionlimit(2000)

def mod_inverse(a, m):
    if a == 0:
        raise ValueError("Cannot calculate inverse of 0")
    if m == 1:
        return 0
    m0, x0, x1 = m, 0, 1
    orig_a = a
    while a > 1:
        try:
            q = a // m
        except ZeroDivisionError:
            raise ValueError("Modulus m cannot be zero")
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    if (orig_a * x1) % m0 != 1:
        raise ValueError(f"Modular inverse does not exist for {orig_a} and {m0}")
    return x1

class EllipticCurve:
    def __init__(self, p, a, b, Gx, Gy, n):
        self.p = p
        self.a = a
        self.b = b
        self.Gx = Gx
        self.Gy = Gy
        self.G = (Gx, Gy)
        self.n = n
        self.infinity = (None, None)

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

secp256k1 = EllipticCurve(p, a, b, Gx, Gy, n)

def is_on_curve(point, curve):
    if point == curve.infinity:
        return True
    x, y = point
    lhs = (y * y) % curve.p
    rhs = (x**3 + curve.a * x + curve.b) % curve.p
    return lhs == rhs

def point_add(P, Q, curve):
    if P == curve.infinity:
        return Q
    if Q == curve.infinity:
        return P
    Px, Py = P
    Qx, Qy = Q
    if Px == Qx and Py == Qy:
        return point_double(P, curve)
    if Px == Qx and (Py != Qy or Py == 0):
        return curve.infinity
    try:
        dy = (Qy - Py) % curve.p
        dx = (Qx - Px) % curve.p
        s = (dy * mod_inverse(dx, curve.p)) % curve.p
    except ValueError:
        return curve.infinity
    Rx = (s**2 - Px - Qx) % curve.p
    Ry = (s * (Px - Rx) - Py) % curve.p
    return (Rx, Ry)

def point_double(P, curve):
    if P == curve.infinity:
        return curve.infinity
    Px, Py = P
    if Py == 0:
        return curve.infinity
    try:
        numerator = (3 * Px**2 + curve.a) % curve.p
        denominator = (2 * Py) % curve.p
        s = (numerator * mod_inverse(denominator, curve.p)) % curve.p
    except ValueError:
        return curve.infinity
    Rx = (s**2 - 2 * Px) % curve.p
    Ry = (s * (Px - Rx) - Py) % curve.p
    return (Rx, Ry)

def scalar_multiply(k, P, curve):
    if k == 0:
        return curve.infinity
    if P == curve.infinity:
        return curve.infinity
    if k < 0:
        k = -k
        P = (P[0], -P[1] % curve.p)
    k = k % curve.n
    if k == 0:
        return curve.infinity
    current = P
    result = curve.infinity
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current, curve)
        current = point_double(current, curve)
        k = k // 2
    return result

def generate_keys(curve):
    d = random.randint(1, curve.n - 1)
    H = scalar_multiply(d, curve.G, curve)
    public_key = H
    private_key = d
    return (public_key, private_key)

def encrypt(public_key, plaintext, curve):
    H = public_key
    ciphertext = []
    try:
        for char in plaintext:
            m = ord(char)
            k = random.randint(1, curve.n - 1)
            C1 = scalar_multiply(k, curve.G, curve)
            S = scalar_multiply(k, H, curve)
            Sx, Sy = S
            if Sx is None:
                continue
            C2 = (m + Sx) % curve.p
            ciphertext.append((C1, C2))
        return ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt(private_key, ciphertext, curve):
    d = private_key
    plaintext_list = []
    try:
        for C1, C2 in ciphertext:
            S = scalar_multiply(d, C1, curve)
            Sx, Sy = S
            if Sx is None:
                continue
            m_int = (C2 - Sx) % curve.p
            plaintext_list.append(chr(m_int))
        return "".join(plaintext_list)
    except ValueError as e:
        print(f"Decryption error: {e}. Possible key mismatch or data corruption.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None

def run_ecc_demo(plaintext):
    secp256k1.p_str = f"0x{secp256k1.p:X}"
    secp256k1.Gx_str = f"0x{secp256k1.G[0]:X}"
    secp256k1.Gy_str = f"0x{secp256k1.G[1]:X}"
    curve = secp256k1
    start_key_gen = time.perf_counter()
    try:
        public_key, private_key = generate_keys(curve)
    except Exception as e:
        print(f"Key Generation FAILED: {e}")
        return
    end_key_gen = time.perf_counter()
    key_gen_time = end_key_gen - start_key_gen
    start_encrypt = time.perf_counter()
    encrypted_msg = encrypt(public_key, plaintext, curve)
    end_encrypt = time.perf_counter()
    encrypt_time = end_encrypt - start_encrypt
    if not encrypted_msg:
        return
    start_decrypt = time.perf_counter()
    decrypted_msg = decrypt(private_key, encrypted_msg, curve)
    end_decrypt = time.perf_counter()
    decrypt_time = end_decrypt - start_decrypt
    total_time = key_gen_time + encrypt_time + decrypt_time
    return key_gen_time, encrypt_time, decrypt_time, total_time

if __name__ == "__main__":
    plaintext_message = "Hello jdaisjdaiosjdajsio!"
    run_ecc_demo(plaintext_message)
