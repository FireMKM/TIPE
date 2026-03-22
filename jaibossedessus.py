import time
import random
import matplotlib.pyplot as plt
import secrets

from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes

## Mon RSA

def my_rsa_generate_keys(key_size):
    p, q = getPrime(int(key_size/2)), getPrime(int(key_size/2))
    n = p * q
    phi_n = (p-1) * (q-1)
    e = 65537
    d = pow(e, -1, phi_n)
    return (n, e), (n, d)


def my_rsa_encrypt(message, public_key):
    cipher = pow(message, public_key[1], public_key[0])
    return cipher


def my_rsa_decrypt(cipher, private_key):
    decipher = pow(cipher, private_key[1], private_key[0])
    return decipher


def my_rsa_test(secret_message, public_key, private_key):
    message = bytes_to_long(secret_message)

    # Encryption
    start = time.perf_counter()
    cipher = my_rsa_encrypt(message, public_key)
    enc_time = time.perf_counter() - start

    # Decryption
    start = time.perf_counter()
    decipher = my_rsa_decrypt(cipher, private_key)
    dec_time = time.perf_counter() - start

    return enc_time, dec_time

## ElGamal

def elgamal_generate_keys(key_size):
    p = getPrime(key_size)
    print(p)
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


def elgamal_test(secret_message, L):
    p, g, x, y = L
    message = bytes_to_long(secret_message)

    # Encryption
    start = time.perf_counter()
    c1, c2 = elgamal_encrypt(p, g, y, message)
    enc_time = time.perf_counter() - start

    # Decryption
    start = time.perf_counter()
    decrypted = elgamal_decrypt(p, x, c1, c2)
    dec_time = time.perf_counter() - start

    return enc_time, dec_time

## Benchmark

key_sizes = [1024, 2048, 3072, 4096]

rsa_enc_times = []
rsa_dec_times = []
elg_enc_times = []
elg_dec_times = []
rsa_key_times = []
elg_key_times = []

bstart=time.perf_counter()

secret_message = long_to_bytes(secrets.randbits(256))

for size in key_sizes:
    print(f"Testing key size: {size} bits")

    start = time.perf_counter()
    elgamal_param = elgamal_generate_keys(size)
    elg_key_times.append(time.perf_counter()-start)

    start = time.perf_counter()
    rsa_param = my_rsa_generate_keys(size)
    rsa_key_times.append(time.perf_counter()-start)

    r_enc, r_dec = my_rsa_test(secret_message, rsa_param[0], rsa_param[1])
    e_enc, e_dec = elgamal_test(secret_message, elgamal_param)

    rsa_enc_times.append(round(r_enc, 8))
    rsa_dec_times.append(round(r_dec, 8))
    elg_enc_times.append(round(e_enc, 8))
    elg_dec_times.append(round(e_dec, 8))

print(f'rsa_enc_times = {rsa_enc_times}')
print(f'rsa_dec_times = {rsa_dec_times}')
print(f'elg_enc_times = {elg_enc_times}')
print(f'elg_dec_times = {elg_dec_times}')
print(f'rsa_key_times = {rsa_key_times}')
print(f'elg_key_times = {elg_key_times}')

btime=round(time.perf_counter()-bstart)

print(f"The algorithm took {btime//60}min{btime%60}s to run")

## Graphs

# Encryption graph
plt.figure()
plt.plot(key_sizes, rsa_enc_times, marker='o', label='RSA Encryption')
plt.plot(key_sizes, elg_enc_times, marker='o', label='ElGamal Encryption')
plt.xlabel("Key size (bits)")
plt.ylabel("Time (seconds)")
plt.title("Encryption Time Comparison")
plt.legend()
plt.grid()
plt.show()

# Decryption graph
plt.figure()
plt.plot(key_sizes, rsa_dec_times, marker='o', label='RSA Decryption')
plt.plot(key_sizes, elg_dec_times, marker='o', label='ElGamal Decryption')
plt.xlabel("Key size (bits)")
plt.ylabel("Time (seconds)")
plt.title("Decryption Time Comparison")
plt.legend()
plt.grid()
plt.show()

# Decryption graph
plt.figure()
plt.plot(key_sizes, rsa_key_times, marker='o', label='RSA Keys Generation')
plt.plot(key_sizes, elg_key_times, marker='o', label='ElGamal Keys Generation')
plt.xlabel("Key size (bits)")
plt.ylabel("Time (seconds)")
plt.title("Key Generation Time Comparison")
plt.legend()
plt.grid()
plt.show()