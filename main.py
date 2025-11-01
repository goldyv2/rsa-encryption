# This program is NOT to be considered a real or proper implementation of RSA encryption.
# This was created out of curiosity and to learn by implementing many fundamentals from scratch.

import secrets
from typing import Optional
from dataclasses import dataclass

@dataclass
class Key:
    rsa_module: int
    exponent: int

def gcd(a: int, b: int) -> int:
    if a <= 0 or b <= 0:
        return 0

    largest = max(a, b)

    for num_to_multiply in range(largest, 0, -1):

        # we use modulus division to check if a and b get's divided evenley.
        if a % num_to_multiply == 0 and b % num_to_multiply == 0:
            return num_to_multiply

    return 1

def euler_totient(number: int) -> int:
    """
    Calculates how many of the numbers less than or equal to 
    this value are coprime (two numbers have no common divisor except 1).
    """
    coprime_count = 0

    for num_to_check in range(1, number):

        if gcd(num_to_check, number) == 1:
            coprime_count += 1

    return coprime_count

def random_encryption_exponent(rsa_module: int) -> int:
    # As we aren't creating a real and secure RSA 
    # implementation we can just limit the randomized number to 8 bits.
    potential_encryption_exponent = secrets.randbits(8)

    # The encryption exponent MUST be a coprime of ϕ(n) and to 
    # check that we can use our gcd and euler totient implementation.
    if gcd(potential_encryption_exponent, euler_totient(rsa_module)) == 1:
        return potential_encryption_exponent

    # python's default max recursion depth is 1000 
    # and the maximum number we can generate is 255 so 
    # we can responsibly use recursion here.
    return random_encryption_exponent(rsa_module)

def find_decryption_exponent(encryption_exponent: int, rsa_module: int) -> Optional[int]:
    decryption_exponent = 1

    coprime_numbers_count = euler_totient(rsa_module)

    while decryption_exponent < coprime_numbers_count:
        if (encryption_exponent * decryption_exponent) % coprime_numbers_count == 1:
            return decryption_exponent

        decryption_exponent += 1

    # should never really happen if correct input is given.
    return None

def generate_rsa_key_pairs(p: int, q: int) -> tuple[Key, Key]:
    """
    Generates and returns public key and private key from p and q prime numbers.

    The first key is the public key and second key is the private key.
    """

    # we get "n" by simply multiplying p and q.
    rsa_module = p * q # aka "n"

    # Now we need to calculate how many of the numbers less than or 
    # equal to "n" are coprime (two numbers have no common divisor except 1) 
    # to "n" so we can get a value for "e" and "d".
    encryption_exponent = random_encryption_exponent(rsa_module) # aka "e"
    decryption_exponent = find_decryption_exponent(encryption_exponent, rsa_module) # aka "d"

    public_key = Key(
        rsa_module,
        exponent = encryption_exponent
    )

    private_key = Key(
        rsa_module,
        exponent = decryption_exponent
    )

    return (public_key, private_key)

if __name__ == "__main__":
    # random prime numbers
    p = 19
    q = 71

    public_key, private_key = generate_rsa_key_pairs(p, q)

    print("public ->", public_key)
    print("private ->", private_key)