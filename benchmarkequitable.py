import time
import random
from statistics import mean
import matplotlib.pyplot as plt

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import getPrime, inverse, bytes_to_long

def rsa_prepare(key_size):
    """
    Génère la clé RSA UNE FOIS (hors benchmark)
    """
    key = RSA.generate(key_size)
    cipher = PKCS1_OAEP.new(key)
    decipher = PKCS1_OAEP.new(key)
    return cipher, decipher


def rsa_benchmark(cipher, decipher, iterations=50):
    """
    Mesure uniquement chiffrement et déchiffrement
    """
    message = b"A"*64

    enc_times = []
    dec_times = []

    for _ in range(iterations):
        start = time.perf_counter()
        ciphertext = cipher.encrypt(message)
        enc_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        decipher.decrypt(ciphertext)
        dec_times.append(time.perf_counter() - start)

    return mean(enc_times), mean(dec_times)


def elgamal_prepare(key_size):
    """
    Génère les paramètres ElGamal UNE FOIS (hors benchmark)
    """
    p = getPrime(key_size)
    g = random.randint(2, p - 2)
    x = random.randint(1, p - 2)  # clé privée
    y = pow(g, x, p)              # clé publique
    return p, g, x, y


def elgamal_encrypt(p, g, y, m):
    k = random.randint(1, p - 2)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2


def elgamal_decrypt(p, x, c1, c2):
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    return (c2 * s_inv) % p


def elgamal_benchmark(p, g, x, y, iterations=50):
    """
    Mesure uniquement chiffrement et déchiffrement
    """
    message = bytes_to_long(b"A"*64)

    enc_times = []
    dec_times = []

    for _ in range(iterations):
        start = time.perf_counter()
        c1, c2 = elgamal_encrypt(p, g, y, message)
        enc_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        elgamal_decrypt(p, x, c1, c2)
        dec_times.append(time.perf_counter() - start)

    return mean(enc_times), mean(dec_times)


key_sizes = [1024, 2048, 3072]

rsa_enc_times = []
rsa_dec_times = []
elg_enc_times = []
elg_dec_times = []

for size in key_sizes:
    print(f"\n=== Niveau de sécurité ~ {size} bits ===")

    # RSA
    rsa_cipher, rsa_decipher = rsa_prepare(size)
    r_enc, r_dec = rsa_benchmark(rsa_cipher, rsa_decipher)

    # ElGamal
    p, g, x, y = elgamal_prepare(size)
    e_enc, e_dec = elgamal_benchmark(p, g, x, y)

    rsa_enc_times.append(r_enc)
    rsa_dec_times.append(r_dec)
    elg_enc_times.append(e_enc)
    elg_dec_times.append(e_dec)


# Graphe chiffrement
plt.figure()
plt.plot(key_sizes, rsa_enc_times, marker='o', label='RSA Encryption')
plt.plot(key_sizes, elg_enc_times, marker='o', label='ElGamal Encryption')
plt.xlabel("Key size (bits)")
plt.ylabel("Time (seconds)")
plt.title("Encryption Time Comparison (Key Generation Excluded)")
plt.legend()
plt.grid()
plt.show()

# Graphe déchiffrement
plt.figure()
plt.plot(key_sizes, rsa_dec_times, marker='o', label='RSA Decryption')
plt.plot(key_sizes, elg_dec_times, marker='o', label='ElGamal Decryption')
plt.xlabel("Key size (bits)")
plt.ylabel("Time (seconds)")
plt.title("Decryption Time Comparison (Key Generation Excluded)")
plt.legend()
plt.grid()
plt.show()
