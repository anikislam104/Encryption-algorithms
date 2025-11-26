import time
import sys
import random

sys.setrecursionlimit(2000)

def generate_keys(p, g):
    a = random.randint(2, p - 2)
    h = pow(g, a, p)
    public_key = (p, g, h)
    private_key = a
    return (public_key, private_key)

def encrypt(public_key, plaintext):
    p, g, h = public_key
    ciphertext = []
    try:
        for char in plaintext:
            m = ord(char)
            k = random.randint(2, p - 2)
            c1 = pow(g, k, p)
            s = pow(h, k, p)
            c2 = (m * s) % p
            ciphertext.append((c1, c2))
        return ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt(private_key, p, ciphertext):
    a = private_key
    plaintext_list = []
    try:
        for c1, c2 in ciphertext:
            s = pow(c1, a, p)
            s_inv = pow(s, p - 2, p)
            m_int = (c2 * s_inv) % p
            plaintext_list.append(chr(m_int))
        return "".join(plaintext_list)
    except ValueError as e:
        print(f"Decryption error: {e}. Possible key mismatch or data corruption.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None

def run_elgamal_demo(plaintext):
    p = 257
    g = 3
    start_key_gen = time.perf_counter()
    try:
        public_key, private_key = generate_keys(p, g)
    except Exception as e:
        print(f"Key Generation FAILED: {e}")
        return
    end_key_gen = time.perf_counter()
    key_gen_time = end_key_gen - start_key_gen
    start_encrypt = time.perf_counter()
    encrypted_msg = encrypt(public_key, plaintext)
    end_encrypt = time.perf_counter()
    encrypt_time = end_encrypt - start_encrypt
    start_decrypt = time.perf_counter()
    decrypted_msg = decrypt(private_key, p, encrypted_msg)
    end_decrypt = time.perf_counter()
    decrypt_time = end_decrypt - start_decrypt
    total_time = key_gen_time + encrypt_time + decrypt_time
    return key_gen_time, encrypt_time, decrypt_time, total_time

if __name__ == "__main__":
    plaintext_message = "Hello! This is an ElGamal test. 123."
    run_elgamal_demo(plaintext_message)
