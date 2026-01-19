import time
import random
import matplotlib.pyplot as plt

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

## Miller Rabin

def is_prime(n, k=40):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

## RSA

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1
        if is_prime(n):
            return n

def mod_inverse(a, m):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y

    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Inverse modulaire inexistant")
    return x % m

def generate_keys(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = random.randrange(2, phi)
        while gcd(e, phi) != 1:
            e = random.randrange(2, phi)

    d = mod_inverse(e, phi)

    return (e, n), (d, n)

def encrypt(message, public_key):
    e, n = public_key
    message_int = int.from_bytes(message.encode(), 'big')
    if message_int >= n:
        raise ValueError("Message trop long")
    cipher = pow(message_int, e, n)
    return cipher

def decrypt(cipher, private_key):
    d, n = private_key
    message_int = pow(cipher, d, n)
    message_bytes = message_int.to_bytes((message_int.bit_length() + 7) // 8, 'big')
    return message_bytes.decode()

def rsa_test(key_size):
    # Génération des clés
    key = generate_keys(key_size)
    cipher = PKCS1_OAEP.new(key)
    decipher = PKCS1_OAEP.new(key)

    message = b"Hello Crypto"

    # Chiffrement
    start = time.perf_counter()
    ciphertext = cipher.encrypt(message)
    enc_time = time.perf_counter() - start

    # Déchiffrement
    start = time.perf_counter()
    plaintext = decipher.decrypt(ciphertext)
    dec_time = time.perf_counter() - start

    return enc_time, dec_time

## ElGamal

def elgamal_generate_keys(key_size):
    p = getPrime(key_size)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)  # clé privée
    y = pow(g, x, p)              # clé publique
    return p, g, x, y


def elgamal_encrypt(p, g, y, message):
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p
    return c1, c2


def elgamal_decrypt(p, x, c1, c2):
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    return (c2 * s_inv) % p


def elgamal_test(key_size):
    p, g, x, y = elgamal_generate_keys(key_size)
    message = bytes_to_long(b"Hello Crypto")

    # Chiffrement
    start = time.perf_counter()
    c1, c2 = elgamal_encrypt(p, g, y, message)
    enc_time = time.perf_counter() - start

    # Déchiffrement
    start = time.perf_counter()
    decrypted = elgamal_decrypt(p, x, c1, c2)
    dec_time = time.perf_counter() - start

    return enc_time, dec_time

## Génération des clés ??

key_sizes = [1024, 2048, 3072, 4096, 5120]

rsa_enc_times = []
rsa_dec_times = []
elg_enc_times = []
elg_dec_times = []

for size in key_sizes:
    print(f"Testing key size: {size} bits")

    r_enc, r_dec = rsa_test(size)
    e_enc, e_dec = elgamal_test(size)

    rsa_enc_times.append(r_enc)
    rsa_dec_times.append(r_dec)
    elg_enc_times.append(e_enc)
    elg_dec_times.append(e_dec)


## Graphes

# Graphe chiffrement
plt.figure()
plt.plot(key_sizes, rsa_enc_times, marker='o', label='RSA Encryption')
plt.plot(key_sizes, elg_enc_times, marker='o', label='ElGamal Encryption')
plt.xlabel("Key size (bits)")
plt.ylabel("Time (seconds)")
plt.title("Encryption Time Comparison")
plt.legend()
plt.grid()
plt.show()

# Graphe déchiffrement
plt.figure()
plt.plot(key_sizes, rsa_dec_times, marker='o', label='RSA Decryption')
plt.plot(key_sizes, elg_dec_times, marker='o', label='ElGamal Decryption')
plt.xlabel("Key size (bits)")
plt.ylabel("Time (seconds)")
plt.title("Decryption Time Comparison")
plt.legend()
plt.grid()
plt.show()
