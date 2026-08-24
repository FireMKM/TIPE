import time
import random
import secrets
import matplotlib.pyplot as plt

from Crypto.Util.number import getPrime, isPrime, inverse, bytes_to_long, long_to_bytes

def moyenne(liste):
    return sum(liste) / len(liste)


# RSA

def my_rsa_generate_keys(key_size):
    p = getPrime(key_size // 2)
    q = getPrime(key_size // 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi_n)
    return (n, e), (n, d)


def my_rsa_encrypt(message, public_key):
    return pow(message, public_key[1], public_key[0])


def my_rsa_decrypt(cipher, private_key):
    return pow(cipher, private_key[1], private_key[0])


def my_rsa_test(secret_message, public_key, private_key):
    message = bytes_to_long(secret_message)

    start = time.perf_counter()
    cipher = my_rsa_encrypt(message, public_key)
    enc_time = time.perf_counter() - start

    start = time.perf_counter()
    decipher = my_rsa_decrypt(cipher, private_key)
    dec_time = time.perf_counter() - start

    assert decipher == message, "RSA : echec de dechiffrement"
    return enc_time, dec_time


# ElGamal

def generate_dsa_like_params(p_size, q_size):
    q = getPrime(q_size)

    h_size = p_size - q_size
    while True:
        h = secrets.randbits(h_size - 1) | (1 << (h_size - 1))
        if h % 2 == 1:
            h += 1
        p = h * q + 1
        if p.bit_length() != p_size:
            continue
        if isPrime(p):
            break

    while True:
        alpha = random.randint(2, p - 2)
        g = pow(alpha, h, p)
        if g != 1:
            break

    return p, q, g


def elgamal_opt_generate_keys(p, q, g):
    x = random.randint(1, q - 1)
    y = pow(g, x, p)
    return x, y


def elgamal_opt_encrypt(p, q, g, y, message):
    k = random.randint(1, q - 1)
    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p
    return c1, c2


def elgamal_opt_decrypt(p, x, c1, c2):
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    return (c2 * s_inv) % p


def elgamal_opt_test(secret_message, params, x, y):
    p, q, g = params
    message = bytes_to_long(secret_message)

    start = time.perf_counter()
    c1, c2 = elgamal_opt_encrypt(p, q, g, y, message)
    enc_time = time.perf_counter() - start

    start = time.perf_counter()
    decrypted = elgamal_opt_decrypt(p, x, c1, c2)
    dec_time = time.perf_counter() - start

    assert decrypted == message, "ElGamal : echec de dechiffrement"
    return enc_time, dec_time


# Benchmark

if __name__ == "__main__":

    p_sizes = [1024, 2048, 3072, 4096]
    Q_SIZE = 256

    rsa_enc_times, rsa_dec_times, rsa_key_times = [], [], []
    elg_enc_times, elg_dec_times, elg_key_times = [], [], []

    bstart = time.perf_counter()
    secret_message = long_to_bytes(secrets.randbits(256))

    for size in p_sizes:
        print(f"\n=== Taille de cle : {size} bits (q = {Q_SIZE} bits) ===")

        # --- Generation des parametres ElGamal ---
        start = time.perf_counter()
        params = generate_dsa_like_params(size, Q_SIZE)
        x, y = elgamal_opt_generate_keys(*params)
        elg_key_time = time.perf_counter() - start
        print(f"Generation cles ElGamal : {elg_key_time:.4f} s")

        # --- Generation des cles RSA ---
        start = time.perf_counter()
        pub, priv = my_rsa_generate_keys(size)
        rsa_key_time = time.perf_counter() - start
        print(f"Generation cles RSA     : {rsa_key_time:.4f} s")

        # --- Tests de chiffrement/dechiffrement ---
        r_enc, r_dec = my_rsa_test(secret_message, pub, priv)
        e_enc, e_dec = elgamal_opt_test(secret_message, params, x, y)

        print(f"RSA      enc/dec : {r_enc:.6f} / {r_dec:.6f} s")
        print(f"ElGamal* enc/dec : {e_enc:.6f} / {e_dec:.6f} s")

        rsa_key_times.append(rsa_key_time)
        elg_key_times.append(elg_key_time)
        rsa_enc_times.append(r_enc)
        rsa_dec_times.append(r_dec)
        elg_enc_times.append(e_enc)
        elg_dec_times.append(e_dec)

    btime = round(time.perf_counter() - bstart)
    print(f"\n>>> Benchmark total : {btime // 60} min {btime % 60} s")
    print(f"rsa_enc_times = {rsa_enc_times}")
    print(f"rsa_dec_times = {rsa_dec_times}")
    print(f"elg_enc_times = {elg_enc_times}")
    print(f"elg_dec_times = {elg_dec_times}")
    print(f"rsa_key_times = {rsa_key_times}")
    print(f"elg_key_times = {elg_key_times}")

    # Graphes

    plt.figure()
    plt.plot(p_sizes, rsa_enc_times, marker='o', label='RSA')
    plt.plot(p_sizes, elg_enc_times, marker='o', label='ElGamal (sous-groupe)')
    plt.xlabel("Taille de p (bits)")
    plt.ylabel("Temps (s)")
    plt.title("Chiffrement -- ElGamal optimise (q = 256 bits)")
    plt.legend()
    plt.grid(True)
    plt.savefig("opt_encryption.png", dpi=120)

    plt.figure()
    plt.plot(p_sizes, rsa_dec_times, marker='o', label='RSA')
    plt.plot(p_sizes, elg_dec_times, marker='o', label='ElGamal (sous-groupe)')
    plt.xlabel("Taille de p (bits)")
    plt.ylabel("Temps (s)")
    plt.title("Dechiffrement -- ElGamal optimise (q = 256 bits)")
    plt.legend()
    plt.grid(True)
    plt.savefig("opt_decryption.png", dpi=120)

    plt.figure()
    plt.plot(p_sizes, rsa_key_times, marker='o', label='RSA')
    plt.plot(p_sizes, elg_key_times, marker='o', label='ElGamal (sous-groupe)')
    plt.xlabel("Taille de p (bits)")
    plt.ylabel("Temps (s)")
    plt.title("Generation des cles -- ElGamal optimise (q = 256 bits)")
    plt.legend()
    plt.grid(True)
    plt.savefig("opt_keygen.png", dpi=120)

    plt.show()
