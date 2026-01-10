import time
import random
import matplotlib.pyplot as plt

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

## RSA

def rsa_test(key_size):
    # Génération des clés
    key = RSA.generate(key_size)
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

key_sizes = [1024, 2048, 3072, 4096, 5120, 6144]

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