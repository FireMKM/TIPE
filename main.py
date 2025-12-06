#!/usr/bin/env python3
"""
crypto_compare.py
Démonstration : ElGamal (groupe cyclique) vs RSA (groupe non-cyclique)
USAGE (demo only): python3 crypto_compare.py
WARNING: for real security use established libraries (PyCryptodome, libsodium) and recommended key sizes.
"""

import secrets, time, math


# -------------------------
# Utils: Miller-Rabin, prime gen, modinv
# -------------------------
def is_probable_prime(n, k=8):
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    # write n-1 as d*2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("No modular inverse")
    return x % m


# -------------------------
# ElGamal (groupe cyclique)
# -------------------------
def elgamal_generate_params(p_bits=512, q_bits=160):
    # Generate q prime, then find p = k*q + 1 with p prime (safe-ish)
    # For demo, simple loop (inefficient for large sizes)
    while True:
        q = generate_prime(q_bits)
        # try small k
        for k in range(2, 5000):
            p = q * k + 1
            if p.bit_length() != p_bits:
                continue
            if is_probable_prime(p):
                # find generator g of order q
                for _ in range(50):
                    h = secrets.randbelow(p - 2) + 2
                    g = pow(h, (p - 1) // q, p)
                    if g != 1:
                        return (p, q, g)
        # retry


def elgamal_keygen(p, q, g):
    x = secrets.randbelow(q - 1) + 1
    h = pow(g, x, p)
    return {'p': p, 'q': q, 'g': g, 'x': x, 'h': h}


def elgamal_encrypt(pub, m):
    p, q, g, h = pub['p'], pub['q'], pub['g'], pub['h']
    if not (0 < m < p):
        raise ValueError("m must be 0 < m < p")
    k = secrets.randbelow(q - 1) + 1
    c1 = pow(g, k, p)
    s = pow(h, k, p)
    c2 = (m * s) % p
    return (c1, c2)


def elgamal_decrypt(priv, c):
    p, x = priv['p'], priv['x']
    c1, c2 = c
    s = pow(c1, x, p)
    s_inv = modinv(s, p)
    m = (c2 * s_inv) % p
    return m


# -------------------------
# RSA (Z_n^* non-cyclique)
# -------------------------
def rsa_keygen(bits=1024):
    e = 65537
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            # Precompute CRT values
            dP = d % (p - 1)
            dQ = d % (q - 1)
            qInv = modinv(q, p)
            priv = {'p': p, 'q': q, 'n': n, 'd': d, 'dP': dP, 'dQ': dQ, 'qInv': qInv}
            pub = {'n': n, 'e': e}
            return pub, priv


def rsa_encrypt(pub, m):
    n, e = pub['n'], pub['e']
    if not (0 <= m < n):
        raise ValueError("m must be in 0..n-1")
    return pow(m, e, n)


def rsa_decrypt_crt(priv, c):
    p, q, dP, dQ, qInv, n = priv['p'], priv['q'], priv['dP'], priv['dQ'], priv['qInv'], priv['n']
    m1 = pow(c % p, dP, p)
    m2 = pow(c % q, dQ, q)
    h = (qInv * (m1 - m2)) % p
    m = (m2 + h * q) % n
    return m


# -------------------------
# Demo / Benchmark
# -------------------------
def demo():
    print("=== Demo: petits paramètres (insecure) pour rapidité ===")
    # ElGamal params (small for demo)
    print("Génération ElGamal (p ~ 512 bits, q ~160 bits) ...")
    p, q, g = elgamal_generate_params(p_bits=512, q_bits=160)
    el_priv = elgamal_keygen(p, q, g)
    el_pub = {'p': p, 'q': q, 'g': g, 'h': el_priv['h']}
    print("ElGamal key ready. p bits:", p.bit_length())

    m = secrets.randbelow(p - 2) + 1
    t0 = time.perf_counter()
    c = elgamal_encrypt(el_pub, m)
    t1 = time.perf_counter()
    m2 = elgamal_decrypt(el_priv, c)
    t2 = time.perf_counter()
    print("ElGamal encrypt time: {:.4f}s, decrypt time: {:.4f}s".format(t1 - t0, t2 - t1))
    assert m == m2

    # RSA params (small for demo)
    print("\nGénération RSA (1024 bits demo) ...")
    pub_rsa, priv_rsa = rsa_keygen(bits=1024)
    n = pub_rsa['n']
    print("RSA key ready. n bits:", n.bit_length())

    m = secrets.randbelow(n - 1) + 1
    t0 = time.perf_counter()
    c = rsa_encrypt(pub_rsa, m)
    t1 = time.perf_counter()
    m2 = rsa_decrypt_crt(priv_rsa, c)
    t2 = time.perf_counter()
    print("RSA encrypt time: {:.4f}s, decrypt (CRT) time: {:.4f}s".format(t1 - t0, t2 - t1))
    assert m == m2

    print("\n=== Bench summary (demo) ===")
    print("ElGamal: p_bits {}, q_bits {}".format(p.bit_length(), q.bit_length()))
    print("RSA: n_bits {}".format(n.bit_length()))
    print("Note: pour usage réel, augmentez les tailles et utilisez libs optimisées.")
