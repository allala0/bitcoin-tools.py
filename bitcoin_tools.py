import random
import hashlib
import base58
import elliptic_curve
import codecs

n = int(1.158 * 10**77 - 1)

G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
     )

p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1


def decompress_public_key(compressed_key):
    x = int(('0x' + compressed_key[2:]), 16)

    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)

    if y % 2 != int(str(compressed_key)[:2]) % 2:
        y = p - y

    rv = '04'
    rv += str(hex(x))[2:]
    for _ in range(len(str(hex(x))[2:]) - len(str(hex(y))[2:])):
        rv += '0'
    rv += str(hex(y))[2:]
    for _ in range(len(str(hex(y))[2:]) - len(str(hex(x))[2:])):
        rv += '0'

    return rv


def compress_public_key(key):
    rv = key[2:][:int((len(key) - 2) / 2)]
    rv = '03' + rv if int(key[2:][int((len(key) - 2) / 2):], 16) % 2 else '02' + rv
    return rv


def get_address(key):
    if len(key) % 2 == 1:
        key += '0'
    key_bytes = codecs.decode(key, 'hex_codec')
    return hash_ripemd160(hash_sha256(key_bytes)).hex()


def encode_address(address):
    version = b'\x00'
    address_bytes = codecs.decode(address, 'hex_codec')
    return encode_base58check(address_bytes, version)


def decode_address(address):
    return decode_base58check(address).hex()[2:]


def encode_private_key(key):
    version = b'\x80'
    key = str(hex(key)[2:])
    if len(key) % 2 == 1:
        key = '0' + key
    key_bytes = codecs.decode(key, 'hex_codec')
    return encode_base58check(key_bytes, version)


def decode_private_key(key):
    return decode_base58check(key).hex()[2:]


def is_on_curve(x, y):
    return (x**3 + 7 - y**2) % p == 0


def hash_sha256(data):
    return hashlib.sha256(data).digest()


def hash_ripemd160(data):
    return hashlib.new('ripemd160', data).digest()


def get_random_private_key():
    return random.randint(0, n - 1)


def get_public_key(private_key):
    public_key = eliptic_curve.multiply(private_key)

    public_key_converted = f'04'
    public_key_converted += str(hex(int(public_key[0])))[2:]
    for i in range(len(str(hex(public_key[0]))) - len(str(hex(public_key[1])))):
        public_key_converted += '0'
    public_key_converted += str(hex(int(public_key[1])))[2:]
    for i in range(len(str(hex(public_key[1]))) - len(str(hex(public_key[0])))):
        public_key_converted += '0'
    return public_key_converted


def encode_base58(data):
    return base58.b58encode(data).decode()


def decode_base58(data):
    return base58.b58decode(data).decode()


def encode_base58check(data, version):

    data_bytes = data
    checksum = hash_sha256(hash_sha256(version + data_bytes))[:4]

    return encode_base58(version + data + checksum)


def decode_base58check(data):
    decoded = base58.b58decode_check(data)
    return decoded


private_key = get_random_private_key()
print(f'Private key: {str(hex(private_key))[2:]}')

encoded_private_key = encode_private_key(private_key)
print(f'Encoded private key: {encoded_private_key}')

decoded_private_key = decode_private_key(encoded_private_key)
print(f'Decoded private key: {decoded_private_key}')

public_key = get_public_key(private_key)
print(f'Public key: {public_key}')

compressed_public_key = compress_public_key(public_key)
print(f'Compressed public key: {compressed_public_key}')

decompressed_public_key = decompress_public_key(compressed_public_key)
print(f'Decompressed public key: {decompressed_public_key}')

compressed_address = get_address(compressed_public_key)
print(f'Compressed address: {compressed_address}')

encoded_compressed_address = encode_address(compressed_address)
print(f'Encoded compressed address: {encoded_compressed_address}')

decoded_compressed_address = decode_address(encoded_compressed_address)
print(f'Decoded compressed address: {decoded_compressed_address}')

decompressed_address = get_address(decompressed_public_key)
print(f'Decompressed address: {decompressed_address}')

encoded_decompressed_address = encode_address(decompressed_address)
print(f'Encoded decompressed address: {encoded_decompressed_address}')

decoded_decompressed_address = decode_address(encoded_decompressed_address)
print(f'Decoded decompressed address: {decoded_decompressed_address}')
