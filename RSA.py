import time
import sys

# Set higher recursion depth for potential deep calculations, though
# our iterative functions avoid this. It's good practice for complex crypto.
sys.setrecursionlimit(2000)

def is_prime(n):
    """
    A simple primality test function.
    Checks if a number n is prime.
    """
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
    """
    Euclidean Algorithm to find the Greatest Common Divisor (GCD) of a and b.
    """
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Extended Euclidean Algorithm to find the modular multiplicative inverse of e mod phi.
    This value 'd' is crucial for the private key.
    
    (e * d) % phi = 1
    
    Note: Python 3.8+ has pow(e, -1, phi) which does this directly.
    We implement it manually here to show the algorithm.
    """
    if phi == 1:
        return 0
    m0, x0, x1 = phi, 0, 1
    
    # Store the original phi value
    orig_phi = phi

    while e > 1:
        # q is quotient
        try:
            q = e // phi
        except ZeroDivisionError:
            print("Error: Division by zero in mod_inverse. e and phi may not be coprime.")
            return None
            
        # phi becomes remainder
        phi, e = e % phi, phi
        
        # Update x0 and x1
        x0, x1 = x1 - q * x0, x0

    # Make x1 positive
    if x1 < 0:
        x1 += orig_phi
        
    return x1

def generate_keypair(p, q):
    """
    Generates the public and private key pairs.
    Takes two distinct prime numbers, p and q, as input.
    """
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("Both numbers must be prime.")
    if p == q:
        raise ValueError("p and q cannot be the same.")

    # n = p * q (Modulus for both keys)
    n = p * q

    # phi(n) = (p - 1) * (q - 1) (Euler's Totient)
    phi = (p - 1) * (q - 1)

    # e = public exponent
    # Choose e such that 1 < e < phi and e is coprime to phi (gcd(e, phi) = 1)
    # 65537 is a common choice, but we'll use a smaller one for this example
    # if 65537 is not valid (i.e., >= phi or not coprime).
    e = 65537
    if e >= phi or gcd(e, phi) != 1:
        e = 17 # Try another common one
    if e >= phi or gcd(e, phi) != 1:
        e = 3 # Try another
    if e >= phi or gcd(e, phi) != 1:
        # Fallback to find the first valid e
        e = 2
        while e < phi:
            if gcd(e, phi) == 1:
                break
            e += 1
        if e == phi:
            raise ValueError("Could not find a valid public exponent 'e'.")

    # d = private exponent
    # Calculate d as the modular inverse of e mod phi
    d = mod_inverse(e, phi)
    
    if d is None:
        raise ValueError("Could not calculate modular inverse. Check p, q, and e.")

    # Public key is (n, e)
    # Private key is (n, d)
    return ((n, e), (n, d))

def encrypt(public_key, plaintext):
    """
    Encrypts a plaintext string using the public key.
    Converts each character to its ASCII/Unicode number and encrypts that number.
    Returns a list of encrypted integers (ciphertext).
    """
    n, e = public_key
    
    # c = (m ^ e) % n
    # We use pow(base, exp, mod) as it's much more efficient
    try:
        ciphertext = [pow(ord(char), e, n) for char in plaintext]
        return ciphertext
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt(private_key, ciphertext):
    """
    Decrypts a list of ciphertext integers using the private key.
    Converts each decrypted number back to its character representation.
    Returns the original plaintext string.
    """
    n, d = private_key
    
    # m = (c ^ d) % n
    # We use pow(base, exp, mod) for efficiency
    try:
        plaintext_list = [chr(pow(char_code, d, n)) for char_code in ciphertext]
        # Join all the characters to form the original string
        return "".join(plaintext_list)
    except ValueError as e:
        # This can happen if a decrypted number is not a valid character code
        print(f"Decryption error: {e}. Possible key mismatch or data corruption.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        return None

def run_rsa_demo(plaintext):
    """
    Runs a full demonstration of the RSA algorithm:
    1. Generates keys
    2. Encrypts the provided plaintext
    3. Decrypts the ciphertext
    4. Prints verification and performance timing
    """
    # For a realistic (but still weak) example, we use primes
    # larger than the max ASCII value (127) or common Unicode (255).
    # Using larger primes like 191 and 223 would be even better.
    # Let's use p=61 and q=53. n = 3233.
    p = 61
    q = 53
    
    # print(f"--- RSA Algorithm Demonstration ---")
    # print(f"Using prime p = {p}")
    # print(f"Using prime q = {q}")
    
    # --- Key Generation ---
    # print("\n1. Generating Keys...")
    start_key_gen = time.perf_counter()
    try:
        public_key, private_key = generate_keypair(p, q)
    except ValueError as e:
        print(f"Key Generation FAILED: {e}")
        return # Exit the function if keys can't be generated
    end_key_gen = time.perf_counter()
    key_gen_time = end_key_gen - start_key_gen
    
    # print(f"   Public Key (n, e):  {public_key}")
    # print(f"   Private Key (n, d): {private_key} (This key must be kept secret!)")

    # --- Encryption ---
    # plaintext = "This is a test of the RSA algorithm. It should work!"
    
    # print(f"\n2. Encrypting Message...")
    # print(f"   Plaintext: '{plaintext}'")
    
    start_encrypt = time.perf_counter()
    encrypted_msg = encrypt(public_key, plaintext)
    end_encrypt = time.perf_counter()
    encrypt_time = end_encrypt - start_encrypt
    
    # if encrypted_msg:
    #     print(f"\n   Encrypted Text (as list of integers):")
    #     # Print a snippet if it's too long
    #     if len(encrypted_msg) > 10:
    #          print(f"   {encrypted_msg[:5]} ... {encrypted_msg[-5:]}")
    #     else:
    #          print(f"   {encrypted_msg}")
    # else:
    #     print("Encryption FAILED.")
    #     return # Exit if encryption failed

    # --- Decryption ---
    # print(f"\n3. Decrypting Message...")
    
    start_decrypt = time.perf_counter()
    decrypted_msg = decrypt(private_key, encrypted_msg)
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
    plaintext_message = "This is a test of the RSA algorithm. It should work!"
    
    # Call the main demonstration function
    run_rsa_demo(plaintext_message)