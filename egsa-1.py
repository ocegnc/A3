## ElGamal Digital Signature Scheme:
##===========================================================================================
# Prerequisite Package:
# pip install pycryptodome
#============================================================================================
import random
from hashlib import sha256
from Crypto.Util.number import getPrime
from math import gcd
#============================================================================================
def generate_large_prime(bits=256):
    return getPrime(bits)

def generate_keys():
    p = generate_large_prime()  
    g = random.randint(2, p - 2)  
    x = random.randint(2, p - 2)  
    
    y = pow(g, x, p)
    return (p, g, y), x  

# Task 1: Preventing Collision Attacks on Hash Functions
# Snippet:
def hash_message(message):
   return int(sha1(message.encode()).hexdigest(), 16) # Hash using SHA-1

# Task 2: The Necessity of Hashing the Message
# Snippet:
def sign_message(message, private_key, public_key):
    p, g, y = public_key
    x = private_key
    h = int.from_bytes(message.encode(), "big") # Convert message to integer
    
    h = hash_message(message, p)  

# Task 3: Improving 'k' Selection for Signature Generation
# Snippet:
    while True:
        k = int(input("Enter a value for k: ")) # Entering for k
        if 1 < k < p - 1 and gcd(k, p - 1) == 1:  
            break

    a = pow(g, k, p) 
    k_inv = pow(k, -1, p - 1)  
    b = (k_inv * (h - x * a)) % (p - 1) 

# Task 4: Attaching the Message to the Signature
# Snippet:
    return a, b  # Return only the signature pair

def verify_signature(message, signature, public_key):
    p, g, y = public_key 
    a, b = signature 

# Task 5: Ensuring Signature Validity Check in verify_signature()
# Snippet:
    
    # Verify the signature ensure 'a' is valid
    if not (1 < a < p):  
        return False
    
    h = hash_message(message, p) 
    
    
    v1 = pow(g, h, p)  
    v2 = (pow(y, a, p) * pow(a, b, p)) % p 

    return v1 == v2  

#============================================================================================
# Main Execution
if __name__ == "__main__":
    print("Generating Secure ElGamal Keys...")
public_key, private_key = generate_keys()
print("Keys Generated!")
print(f"Public Key: {public_key}")
print(f"Private Key: {private_key}")

message = input("Enter a Message to Sign:")

signature = sign_message(message, private_key, public_key)
print(f"Signature (a, b): {signature}")

is_valid = verify_signature(message, signature, public_key)
print("Signature Valid?", is_valid)

tampered_message = input("Enter a modified message for testing tampering: ")
is_valid_tampered = verify_signature(tampered_message, signature, public_key)
print("Signature Valid on Modified Message?", is_valid_tampered)