import random
from math import gcd
from sympy import isprime

def generate_keys(bit_length=256):
    """
    Generate ElGamal public and private keys
    Returns: (public_key, private_key) where public_key = (p, g, h) and private_key = (p, g, x)
    """
    # Generate a large prime p
    while True:
        p = random.getrandbits(bit_length)
        if isprime(p):
            break
    
    # Find a generator g for the multiplicative group modulo p
    def is_generator(g, p):
        if gcd(g, p) != 1:
            return False
        order = p - 1
        factors = prime_factors(order)
        for factor in set(factors):
            if pow(g, order // factor, p) == 1:
                return False
        return True
    
    while True:
        g = random.randint(2, p-1)
        if is_generator(g, p):
            break
    
    # Choose private key x
    x = random.randint(1, p-2)
    
    # Compute h = g^x mod p
    h = pow(g, x, p)
    
    public_key = (p, g, h)
    private_key = (p, g, x)
    
    return public_key, private_key

def prime_factors(n):
    """Return a list of prime factors of n (with multiplicity)"""
    i = 2
    factors = []
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.append(i)
    if n > 1:
        factors.append(n)
    return factors

def encrypt(public_key, plaintext):
    """
    Encrypt a message using ElGamal
    public_key: (p, g, h)
    plaintext: integer message to encrypt (must be < p)
    Returns: (c1, c2) ciphertext pair
    """
    p, g, h = public_key
    if plaintext >= p:
        raise ValueError("Plaintext must be less than p")
    
    # Choose random y
    y = random.randint(1, p-2)
    
    # Compute c1 = g^y mod p
    c1 = pow(g, y, p)
    
    # Compute s = h^y mod p
    s = pow(h, y, p)
    
    # Compute c2 = (plaintext * s) mod p
    c2 = (plaintext * s) % p
    
    return (c1, c2)

def decrypt(private_key, ciphertext):
    """
    Decrypt an ElGamal ciphertext
    private_key: (p, g, x)
    ciphertext: (c1, c2)
    Returns: decrypted plaintext
    """
    p, g, x = private_key
    c1, c2 = ciphertext
    
    # Compute s = c1^x mod p
    s = pow(c1, x, p)
    
    # Compute modular inverse of s
    s_inv = pow(s, -1, p)
    
    # Recover plaintext
    plaintext = (c2 * s_inv) % p
    
    return plaintext

# Example usage
if __name__ == "__main__":
    print("Generating ElGamal keys...")
    public_key, private_key = generate_keys(bit_length=64)  # Using 64 bits for demo
    print(f"Public key (p, g, h): {public_key}")
    print(f"Private key (p, g, x): {private_key[0:2]}, x (kept secret)")
    
    message = 1273  # Must be less than p
    print(f"\nOriginal message: {message}")
    
    ciphertext = encrypt(public_key, message)
    print(f"Encrypted ciphertext (c1, c2): {ciphertext}")
    
    decrypted = decrypt(private_key, ciphertext)
    print(f"Decrypted message: {decrypted}")
    
    # Verification
    if message == decrypted:
        print("Success! The decrypted message matches the original.")
    else:
        print("Error in decryption!")