import time

from smartcard.System import readers

r = readers()
connection = r[0].createConnection()
connection.connect()

#SELECT = [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0,0x00,0x00,0x00,0x62,0x03,0x01,0x0C]
#data, sw1, sw2 = connection.transmit(SELECT)

applet_selection = [0x00, 0xA4, 0x04, 0x00, 0x09, 0xFF, 0x53, 0x56, 0x6F, 0x78, 0xFF, 0x22, 0x11, 0x01]
hello_world = [0x22, 0xFF, 0x00, 0x00, 0x07]
encrypt_apdu = [0x22, 0x10, 0x01, 0x00, 0x07, 0x42, 0x6f, 0x6e, 0x6a, 0x6f, 0x75, 0x72, 0x80]

connection.transmit(applet_selection)
print('-------- RSA ENCRYPTION --------')
start = time.perf_counter()
data, sw1, sw2 = connection.transmit(encrypt_apdu)
rsa_enc_time = time.perf_counter() - start

print(f'Encrypted data: {data}')
print(f'({hex(sw1)} {hex(sw2)})')
print(f'rsa_enc_time: {rsa_enc_time}')

print('-------- RSA DECRYPTION --------')
decrypt_apdu = [0x22, 0x10, 0x02, 0x00, 0x80] + data + [0x80]
start = time.perf_counter()
message, sw1, sw2 = connection.transmit(decrypt_apdu)
rsa_dec_time = time.perf_counter() - start

print(f'Decrypted message: {message}')
print(f'({hex(sw1)} {hex(sw2)})')
print(f'rsa_dec_time: {rsa_dec_time}')
