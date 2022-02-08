import random
import hashlib
import base58
import elliptic_curve
import codecs
import binascii
import hmac

n = int(1.158 * 10**77 - 1)

G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
     )

p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1


def fix_hex_len(element, length):
    for _ in range(length - len(element)):
        element = '0' + element
    return element


def hex_to_bytes(hex_value, min_num_of_bytes=0):
    if type(hex_value) != str:
        raise Exception('Hex value need to be string.')
    if len(hex_value) % 2 == 1:
        hex_value = '0' + hex_value

    rv = bytes.fromhex(hex_value)

    for _ in range(min_num_of_bytes - len(rv)):
        rv = bytes(1) + rv
    return rv


def compress_private_key(key: str) -> str:
    return key + '01'


def decompress_public_key(compressed_key: str) -> str:
    x = int(('0x' + compressed_key[2:]), 16)

    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)

    if y % 2 != int(str(compressed_key)[:2]) % 2:
        y = p - y

    rv = '04'
    rv += fix_hex_len(hex(x)[2:], 64)
    rv += fix_hex_len(hex(y)[2:], 64)
    return rv


def compress_public_key(key: str) -> str:
    rv = key[2:][:int((len(key) - 2) / 2)]
    rv = '03' + rv if int(key[2:][int((len(key) - 2) / 2):], 16) % 2 else '02' + rv
    rv = fix_hex_len(rv, 66)
    return rv


def get_address(key: str) -> str:
    if len(key) % 2 == 1:
        # This if need to be tested
        key += '0'
    key_bytes = codecs.decode(key, 'hex_codec')
    return hash_ripemd160(hash_sha256(key_bytes).digest()).hexdigest()


def encode_address(address: str) -> str:
    version = b'\x00'
    address_bytes = codecs.decode(address, 'hex_codec')
    return encode_base58check(address_bytes, version)


def decode_address(address: str) -> str:
    return decode_base58check(address).hex()[2:]


def encode_private_key(key: str) -> str:
    version = b'\x80'
    if len(key) % 2 == 1:
        key = '0' + key
    key_bytes = codecs.decode(key, 'hex_codec')
    return encode_base58check(key_bytes, version)


def decode_private_key(key: str) -> str:
    return decode_base58check(key).hex()[2:]


def is_on_curve(x: int, y: int) -> bool:
    return (x**3 + 7 - y**2) % p == 0


def hash_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data)


def hash_ripemd160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', data)


def get_random_private_key() -> str:
    # Not sure if use p or n as maximum
    private_key = fix_hex_len(hex(random.randint(0, n - 1))[2:], 64)
    return private_key


def get_public_key(private_key: str) -> str:
    public_key = elliptic_curve.multiply(G, int(private_key, 16), p)
    public_key_converted = f'04'
    public_key_converted += fix_hex_len(hex(int(public_key[0]))[2:], 64)
    public_key_converted += fix_hex_len(hex(int(public_key[1]))[2:], 64)

    return public_key_converted


def get_compressed_public_key(private_key: str) -> str:
    return compress_public_key(get_public_key(private_key))


# def encode_public_key(public_key):
#     return encode_base58check(bytes.fromhex(public_key), bytes.fromhex('00'))
#     # return encode_base58(bytes.fromhex('a6341e'))


def encode_base58(data: bytes) -> str:
    return base58.b58encode(data).decode()


# def decode_base58(data):
#     return base58.b58decode(data).decode()


def encode_base58check(data: bytes, version: bytes) -> str:
    checksum = hash_sha256(hash_sha256(version + data).digest()).digest()[:4]
    return encode_base58(version + data + checksum)


def decode_base58check(data: str) -> bytes:
    decoded = base58.b58decode_check(data)
    return decoded


def generate_vanity_address(searched_value: str, any_case: bool = False, any_position: bool = False) -> dict:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    for letter in searched_value:
        if letter not in alphabet:
            raise Exception(f'Argument searched_value="{searched_value}" contains non Base58 characters.')

    while True:
        private_key = get_random_private_key()
        compressed_private_key = compress_private_key(private_key)
        encoded_compressed_private_key = encode_private_key(compressed_private_key)

        compressed_public_key = get_compressed_public_key(private_key)

        compressed_address = get_address(compressed_public_key)
        encoded_compressed_address = encode_address(compressed_address)

        searched_value_buffer = searched_value.lower() if any_case else searched_value

        address_buffer = encoded_compressed_address.lower() if any_case else encoded_compressed_address
        check = searched_value_buffer in address_buffer if any_position else searched_value_buffer == address_buffer[1: len(searched_value) + 1]

        if check:
            vanity_address = {'private key': encoded_compressed_private_key, 'public key': compressed_public_key, 'address': encoded_compressed_address}

            return vanity_address


def generate_mnemonic(words_num: int) -> str:
    if words_num % 3 != 0:
        raise Exception('words_num need to be divisible by 3')

    random_data = ''
    for _ in range(words_num * 11 - words_num // 3):
        random_data += str(random.randint(0, 1))

    random_data_bin = int(random_data, 2)
    random_data_bytes = random_data_bin.to_bytes((random_data_bin.bit_length() + 7) // 8, byteorder='big')

    hash_ = hash_sha256(random_data_bytes).hexdigest()
    hash_bin = bin(int(hash_, 16))[2:]

    hash_bin = fix_hex_len(hash_bin, 256)

    checksum = hash_bin[:words_num // 3]
    data_with_checksum = random_data + checksum

    mnemonic_index = [int(data_with_checksum[i * 11:i * 11 + 11], 2) for i in range(len(data_with_checksum) // 11)]

    with open('bip39/english.txt') as file:
        word_list = file.read().split('\n')

    mnemonic = []
    for index in mnemonic_index:
        mnemonic.append(word_list[index])

    mnemonic_str = ''

    for word in mnemonic:
        mnemonic_str += word + ' '

    return mnemonic_str.strip()


def mnemonic_to_bin(mnemonic: str) -> str:
    mnemonic = mnemonic.strip()
    with open('bip39/english.txt') as file:
        word_list = file.read().split('\n')

    indexes = ''
    for word in mnemonic.split(' '):
        for index in range(len(word_list)):
            if word == word_list[index]:
                index_bin = fix_hex_len(bin(index)[2:], 11)
                indexes += index_bin
    return indexes


def generate_seed(mnemonic: str, passphrase: str = '') -> str:
    return binascii.hexlify(hashlib.pbkdf2_hmac('sha512', bytes(mnemonic.strip().encode()), bytes(f'mnemonic{passphrase}'.encode()), 2048)).decode()


def generate_master_private_key(seed: str) -> dict:
    message = bytes.fromhex(seed)
    key = bytes('Bitcoin seed'.encode())
    hash = hmac.new(key, message, 'sha512').hexdigest()

    hash_bin = bin(int(hash, 16))[2:]
    hash_bin = fix_hex_len(hash_bin, 512)

    master_private_key = hex(int(hash_bin[:256], 2))[2:]
    master_chain_code = hex(int(hash_bin[256:], 2))[2:]

    return {'private_key': master_private_key, 'chain_code': master_chain_code}


def generate_child_extended_key(version: str, parent_private_key: str, parent_chain_code: str, index: int or str) -> dict:
    if type(index) == str:
        if index[len(index) - 1] == "'":
            index = int(index[0:len(index) - 1], 10) + 2**31
        else:
            index = int(index, 10)

    if index >= 2**32:
        raise Exception('Index need to be number 0 <= index <= 2^32')
    if version != 'public' and version != 'private':
        raise Exception('Version must be "private" or "public"')

    if index >= 2**31:
        if version == 'public':
            raise Exception('indexes from 2**31 to 2**32-1 are reserved for hardened extended private keys only.')
    if version == 'public':
        parent_public_key = get_compressed_public_key(parent_private_key)
        parent_private_key = parent_public_key
    if version == 'private':
        if index >= 2**31:
            parent_public_key = '00' + parent_private_key
        else:
            parent_public_key = get_compressed_public_key(parent_private_key)
    key = hex_to_bytes(parent_chain_code)
    message = hex_to_bytes(parent_public_key) + hex_to_bytes(hex(index)[2:], min_num_of_bytes=4)

    hash = hmac.new(key, message, 'sha512').hexdigest()
    # Idk if it should be %n or not in child_private_key
    child_private_key = hex(int(parent_private_key, 16) + int(hash[:64], 16))[2:]
    child_chain_code = hash[64:]

    return {'private_key': child_private_key, 'chain_code': child_chain_code}


def encode_extended_key(version: str, key: str, chain_code: str, depth: int, index: int, parent_public_key: str = None):
    if version == 'private':
        key = '00' + key
        version_code = b'\x04\x88\xad\xe4'
    elif version == 'public':
        version_code = b'\x04\x88\xb2\x1e'
    else:
        raise Exception('Version need to be "private" or "public".')

    if parent_public_key is None:
        parent_fingerprint = bytes(4)
    else:
        parent_fingerprint = hash_ripemd160(parent_public_key.encode())[:4]

    extended_key_bytes = hex_to_bytes(str(depth), min_num_of_bytes=4) + parent_fingerprint + hex_to_bytes(str(index)) + hex_to_bytes(chain_code) + hex_to_bytes(key)

    return encode_base58check(extended_key_bytes, version_code)
