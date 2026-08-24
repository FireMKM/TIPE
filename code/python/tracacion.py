import matplotlib.pyplot as plt

key_sizes = [1024, 2048, 3072, 4096]
rsa_enc_times, rsa_dec_times, elg_enc_times, elg_dec_times, rsa_key_times, elg_key_times= [3.096e-05, 9.512e-05, 0.00018738, 0.0003887], [0.00235717, 0.09787188, 0.21337174, 0.61160156], [0.00472174, 0.19255284, 0.59245415, 1.30162771], [0.00246156, 0.10079064, 0.29277296, 0.69388531], [0.2863687059998483, 4.403855075999672, 5.297632360000534, 16.40351955999995], [0.2040486289997716, 6.101149905999591, 16.493439572999705, 32.39968914400015]

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