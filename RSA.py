import time
import sys

sys.setrecursionlimit(2000)

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    if phi == 1:
        return 0
    m0, x0, x1 = phi, 0, 1
    orig_phi = phi
    while e > 1:
        try:
            q = e // phi
        except ZeroDivisionError:
            print("Error: Division by zero in mod_inverse. e and phi may not be coprime.")
            return None
        phi, e = e % phi, phi
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += orig_phi
    return x1

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    if p == q:
        raise ValueError("p and q cannot be the same.")
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if e >= phi or gcd(e, phi) != 1:
        e = 17
    if e >= phi or gcd(e, phi) != 1:
        e = 3
    if e >= phi or gcd(e, phi) != 1:
        e = 2
        while e < phi:
            if gcd(e, phi) == 1:
                break
            e += 1
        if e == phi:
            raise ValueError("Could not find a valid public exponent 'e'.")
    d = mod_inverse(e, phi)
    if d is None:
        raise ValueError("Could not calculate modular inverse. Check p, q, and e.")
    return ((n, e), (n, d))

def encrypt(public_key, plaintext):
    n, e = public_key
    try:
        ciphertext = [pow(ord(char), e, n) for char in plaintext]
        return ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt(private_key, ciphertext):
    n, d = private_key
    try:
        plaintext_list = [chr(pow(char_code, d, n)) for char_code in ciphertext]
        return "".join(plaintext_list)
    except ValueError as e:
        print(f"Decryption error: {e}. Possible key mismatch or data corruption.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None

def run_rsa_demo(plaintext):
    p = 61
    q = 53
    start_key_gen = time.perf_counter()
    try:
        public_key, private_key = generate_keypair(p, q)
    except ValueError as e:
        print(f"Key Generation FAILED: {e}")
        return
    end_key_gen = time.perf_counter()
    key_gen_time = end_key_gen - start_key_gen
    start_encrypt = time.perf_counter()
    encrypted_msg = encrypt(public_key, plaintext)
    end_encrypt = time.perf_counter()
    encrypt_time = end_encrypt - start_encrypt
    start_decrypt = time.perf_counter()
    decrypted_msg = decrypt(private_key, encrypted_msg)
    end_decrypt = time.perf_counter()
    decrypt_time = end_decrypt - start_decrypt
    total_time = key_gen_time + encrypt_time + decrypt_time
    return key_gen_time, encrypt_time, decrypt_time, total_time

plaintext_message = "This is a test of the RSA algorithm. It should work!"
run_rsa_demo(plaintext_message)
