import time
import sys
import random

# Set higher recursion depth, although our iterative functions avoid this.
sys.setrecursionlimit(2000)

def generate_keys(p, g):
    """
    Generates the public and private key pairs for ElGamal.
    Takes a large prime 'p' and a primitive root 'g' (generator).
    """
    
    # a = private key: Choose a random integer 'a' such that 1 < a < p-2
    a = random.randint(2, p - 2)
    
    # h = public key component: Calculate h = g^a mod p
    # pow(base, exp, mod) is used for efficient modular exponentiation
    h = pow(g, a, p)
    
    # Public key is (p, g, h)
    # Private key is 'a'
    public_key = (p, g, h)
    private_key = a
    
    return (public_key, private_key)

def encrypt(public_key, plaintext):
    """
    Encrypts a plaintext string using the ElGamal public key.
    
    For each character 'm':
    1. Choose a random ephemeral key 'k' (1 < k < p-2)
    2. Calculate c1 = g^k mod p
    3. Calculate s = h^k mod p  (the shared secret)
    4. Calculate c2 = m * s mod p
    
    The ciphertext for 'm' is the pair (c1, c2).
    Returns a list of (c1, c2) pairs.
    """
    p, g, h = public_key
    
    ciphertext = []
    
    try:
        # Encrypt one character at a time
        for char in plaintext:
            # Convert character to its integer representation
            m = ord(char)
            
            # 1. Choose a random ephemeral key 'k'
            k = random.randint(2, p - 2)
            
            # 2. Calculate c1
            c1 = pow(g, k, p)
            
            # 3. Calculate s (the shared secret)
            s = pow(h, k, p)
            
            # 4. Calculate c2
            c2 = (m * s) % p
            
            # Add the (c1, c2) pair to our ciphertext list
            ciphertext.append((c1, c2))
            
        return ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt(private_key, p, ciphertext):
    """
    Decrypts a list of ciphertext (c1, c2) pairs using the private key.
    
    For each (c1, c2) pair:
    1. Calculate s = c1^a mod p
    2. Calculate s_inv = s^(p-2) mod p 
       (This is the modular inverse using Fermat's Little Theorem, s * s_inv % p = 1)
    3. Calculate m = c2 * s_inv mod p
    
    Returns the original plaintext string.
    """
    a = private_key
    
    plaintext_list = []
    
    try:
        for c1, c2 in ciphertext:
            # 1. Calculate s
            s = pow(c1, a, p)
            
            # 2. Calculate s_inv (modular inverse of s mod p)
            # We use pow(s, p - 2, p) which is s^(p-2) % p
            s_inv = pow(s, p - 2, p)
            
            # 3. Calculate m
            m_int = (c2 * s_inv) % p
            
            # Convert integer back to character
            plaintext_list.append(chr(m_int))
            
        # Join all the characters to form the original string
        return "".join(plaintext_list)
        
    except ValueError as e:
        print(f"Decryption error: {e}. Possible key mismatch or data corruption.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None

def run_elgamal_demo(plaintext):
    """
    Runs a full demonstration of the ElGamal algorithm:
    1. Generates keys
    2. Encrypts the provided plaintext
    3. Decrypts the ciphertext
    4. Prints verification and performance timing
    """
    
    # We need a prime 'p' and a primitive root 'g'.
    # 'p' must be larger than the max value of our message characters (e.g., 255 for 8-bit ASCII).
    # p = 257 is a prime number (257 > 255).
    # g = 3 is a primitive root modulo 257.
    p = 257
    g = 3
    
    # print(f"--- ElGamal Algorithm Demonstration ---")
    # print(f"Using prime p = {p}")
    # print(f"Using generator g = {g}")
    
    # --- Key Generation ---
    # print("\n1. Generating Keys...")
    start_key_gen = time.perf_counter()
    try:
        public_key, private_key = generate_keys(p, g)
    except Exception as e:
        print(f"Key Generation FAILED: {e}")
        return # Exit the function
    end_key_gen = time.perf_counter()
    key_gen_time = end_key_gen - start_key_gen
    
    # print(f"   Public Key (p, g, h): {public_key}")
    # print(f"   Private Key (a):    {private_key} (This key must be kept secret!)")

    # # --- Encryption ---
    # print(f"\n2. Encrypting Message...")
    # print(f"   Plaintext: '{plaintext}'")
    
    start_encrypt = time.perf_counter()
    encrypted_msg = encrypt(public_key, plaintext)
    end_encrypt = time.perf_counter()
    encrypt_time = end_encrypt - start_encrypt
    
    # if encrypted_msg:
    #     print(f"\n   Encrypted Text (list of (c1, c2) pairs):")
    #     # Print a snippet if it's too long
    #     if len(encrypted_msg) > 6:
    #          print(f"   {encrypted_msg[:3]} ... {encrypted_msg[-3:]}")
    #     else:
    #          print(f"   {encrypted_msg}")
    # else:
    #     print("Encryption FAILED.")
    #     return # Exit if encryption failed

    # --- Decryption ---
    # print(f"\n3. Decrypting Message...")
    
    start_decrypt = time.perf_counter()
    # Note: Decryption only needs the private key 'a' and the public prime 'p'
    decrypted_msg = decrypt(private_key, p, encrypted_msg)
    end_decrypt = time.perf_counter()
    decrypt_time = end_decrypt - start_decrypt

    # if decrypted_msg:
    #     print(f"   Decrypted Plaintext: '{decrypted_msg}'")
    # else:
    #     print("Decryption FAILED.")
    #     return # Exit if decryption failed

    # --- Verification and Performance ---
    # print("\n--- Verification ---")
    # if plaintext == decrypted_msg:
    #     print("   SUCCESS: Decrypted text matches original plaintext.")
    # else:
    #     print("   FAILURE: Decrypted text does NOT match original plaintext.")

    # print("\n--- Performance ---")
    # print(f"   Key Generation Time: {(key_gen_time * 1000):.6f} milliseconds")
    # print(f"   Encryption Time:     {(encrypt_time * 1000):.6f} milliseconds")
    # print(f"   Decryption Time:     {(decrypt_time * 1000):.6f} milliseconds")
    
    total_time = key_gen_time + encrypt_time + decrypt_time
    # print(f"   Total Time:          {(total_time * 1000):.6f} milliseconds")
    return key_gen_time, encrypt_time, decrypt_time, total_time

# --- Main execution ---
if __name__ == "__main__":
    
    # Define the plaintext message here
    plaintext_message = "Hello! This is an ElGamal test. 123."
    
    # Call the main demonstration function
    run_elgamal_demo(plaintext_message)