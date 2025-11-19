# This program is NOT to be considered a real or proper implementation of RSA encryption.
# This was created out of curiosity and to learn by implementing many fundamentals from scratch 
# hence why I didn't just use the algorithms like (gcd) python provides.

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
        # (e x d) mod ϕ(n) = 1
        if (encryption_exponent * decryption_exponent) % coprime_numbers_count == 1:
            return decryption_exponent

        decryption_exponent += 1

    # should never really happen if correct input is given.
    return None

if __name__ == "__main__":
    # random prime numbers
    p = 83
    q = 59

    # Generate a public key and private key from p and q prime numbers.

    # we get "n" by simply multiplying p and q.
    rsa_module = p * q # aka "n"

    print(f"rsa module (n) --> {rsa_module}")

    # Now we need to calculate how many of the numbers less than or 
    # equal to "n" are coprime (two numbers have no common divisor except 1) 
    # to "n" so we can get a value for "e" and "d".

    # encryption_exponent = 2519
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

    print("public ->", public_key)
    print("private ->", private_key)

    # now time to actually encrypt a message and decrypt it with the pairs
    message = 369

    print(f"message (m) --> {message}")

    if message > rsa_module or message < 0:
        print("Message must be greater or equal to 0 and must be bigger than rsa module!")
        exit(1)

    # we now encrypt the message using the public key encryption exponent.
    cipher = message ** public_key.exponent % public_key.rsa_module

    print(f"cipher (c) --> {cipher}")

    # now let's decrypt the message using the inverse formula
    deciphered_message = cipher ** private_key.exponent % private_key.rsa_module

    print(f"decrypted message (m) --> {deciphered_message}")

    # same exact message
    assert message == deciphered_message