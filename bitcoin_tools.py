import random
import hashlib
import base58
import elliptic_curve
import codecs
import binascii
import hmac

n = 115792089237316195423570985008687907852837564279074904382605163141518161494337
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
     )

p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1


def hash160(data: bytes):
    return hash_ripemd160(hash_sha256(data).digest())


def fix_str_len(element: str, length: int) -> str:
    for _ in range(length - len(element)):
        element = '0' + element
    return element


def hex_to_bytes(hex_value: str, min_num_of_bytes: int = 0):
    if type(hex_value) != str:
        raise Exception('Hex value need to be hex string.')
    if len(hex_value) % 2 == 1:
        hex_value = '0' + hex_value

    rv = bytes.fromhex(hex_value)

    for _ in range(min_num_of_bytes - len(rv)):
        rv = bytes(1) + rv
    return rv


def compress_private_key(private_key: str) -> str:
    return private_key + '01'


def point_to_public_key(point: tuple) -> str:
    return f'04{hex(point[0])[2:]}{hex(point[1])[2:]}'


def public_key_to_point(public_key: str) -> tuple:
    return int(public_key[2:][:64], 16), int(public_key[2:][64:], 16)


def decompress_private_key(private_key: str) -> str:
    if private_key[-2:] != '01':
        raise Exception('Compressed private key must end with 01')
    return private_key[:-2]


def decompress_public_key(compressed_key: str) -> str:
    x = int(('0x' + compressed_key[2:]), 16)

    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)

    if y % 2 != int(str(compressed_key)[:2]) % 2:
        y = p - y

    rv = '04'
    rv += fix_str_len(hex(x)[2:], 64)
    rv += fix_str_len(hex(y)[2:], 64)
    return rv


def compress_public_key(key: str) -> str:
    rv = key[2:][:int((len(key) - 2) / 2)]
    rv = '03' + rv if int(key[2:][int((len(key) - 2) / 2):], 16) % 2 else '02' + rv
    rv = fix_str_len(rv, 66)
    return rv


def get_address(key: str) -> str:
    if len(key) % 2 == 1:
        # This if need to be tested
        key += '0'
    key_bytes = codecs.decode(key, 'hex_codec')
    return hash160(key_bytes).hexdigest()


def encode_address(address: str, p2sh: bool = False, test_net: bool = False) -> str:
    version = b'\x05' if p2sh else b'\x00'
    if test_net:
        version = b'\x6f'
    address_bytes = codecs.decode(address, 'hex_codec')
    return encode_base58check(address_bytes, version)


# TODO!!!
def encrypt_private_key_bip38(private_key: str, password: str) -> str:
    pass


# TODO!!!
def decrypt_private_key_bip38(private_key: str, password: str) -> str:
    pass


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


def generate_random_private_key() -> str:
    # Not sure if use p or n as maximum
    private_key = fix_str_len(hex(random.randint(0, n - 1))[2:], 64)
    return private_key


def get_public_key(private_key: str) -> str:
    public_key = elliptic_curve.multiply(G, int(private_key, 16), p)
    public_key_converted = f'04'
    public_key_converted += fix_str_len(hex(int(public_key[0]))[2:], 64)
    public_key_converted += fix_str_len(hex(int(public_key[1]))[2:], 64)

    return public_key_converted


def get_compressed_public_key(private_key: str) -> str:
    return compress_public_key(get_public_key(private_key))


def encode_base58(data: bytes) -> str:
    return base58.b58encode(data).decode()


def decode_base58(data: str) -> bytes:
    return base58.b58decode(data)


def encode_base58check(data: bytes, version: bytes) -> str:
    checksum = hash_sha256(hash_sha256(version + data).digest()).digest()[:4]
    return encode_base58(version + data + checksum)


def decode_base58check(data: str) -> bytes:
    return base58.b58decode_check(data)


def generate_vanity_address(search_value: str, any_case: bool = False, any_position: bool = False) -> dict:
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    for letter in search_value:
        if letter not in alphabet:
            raise Exception(f'Argument searched_value="{search_value}" contains non Base58 characters.')

    while True:
        private_key = generate_random_private_key()
        compressed_private_key = compress_private_key(private_key)
        encoded_compressed_private_key = encode_private_key(compressed_private_key)

        compressed_public_key = get_compressed_public_key(private_key)

        compressed_address = get_address(compressed_public_key)
        encoded_compressed_address = encode_address(compressed_address)

        searched_value_buffer = search_value.lower() if any_case else search_value

        address_buffer = encoded_compressed_address.lower() if any_case else encoded_compressed_address
        check = searched_value_buffer in address_buffer if any_position else searched_value_buffer == address_buffer[1: len(search_value) + 1]

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

    hash_bin = fix_str_len(hash_bin, 256)

    checksum = hash_bin[:words_num // 3]
    data_with_checksum = random_data + checksum

    mnemonic_str = mnemonic_from_bin(data_with_checksum)

    return mnemonic_str.strip()


def mnemonic_from_bin(mnemonic_bin: str) -> str:

    mnemonic_index = [int(mnemonic_bin[i * 11:i * 11 + 11], 2) for i in range(len(mnemonic_bin) // 11)]

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
                index_bin = fix_str_len(bin(index)[2:], 11)
                indexes += index_bin
    return indexes


def get_seed(mnemonic: str, passphrase: str = '') -> str:
    return binascii.hexlify(hashlib.pbkdf2_hmac('sha512', bytes(mnemonic.strip().encode()), bytes(f'mnemonic{passphrase}'.encode()), 2048)).decode()


def generate_master_private_key(seed: str) -> str:
    message = bytes.fromhex(seed)
    key = bytes('Bitcoin seed'.encode())
    hash = hmac.new(key, message, 'sha512').hexdigest()

    hash_bin = bin(int(hash, 16))[2:]
    hash_bin = fix_str_len(hash_bin, 512)

    master_private_key = fix_str_len(hex(int(hash_bin[:256], 2))[2:], 64)
    master_chain_code = fix_str_len(hex(int(hash_bin[256:], 2))[2:], 64)

    return f'{master_chain_code}{master_private_key}'


def generate_child_extended_key(parent_extended_private_key: str, index: int or str, version: str = 'private') -> str:
    parent_private_key = parent_extended_private_key[64:]
    parent_chain_code = parent_extended_private_key[:64]
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
        n_ = 1
    if version == 'private':
        n_ = n
        if index >= 2**31:
            parent_public_key = '00' + parent_private_key
        else:
            parent_public_key = get_compressed_public_key(parent_private_key)
    key = hex_to_bytes(parent_chain_code)
    message = hex_to_bytes(parent_public_key) + hex_to_bytes(hex(index)[2:], min_num_of_bytes=4)

    hash = hmac.new(key, message, 'sha512').hexdigest()
    # Idk if it should be %n or not in child_private_key

    if version == 'private':
        child_key = fix_str_len(hex((int(parent_private_key, 16) + int(hash[:64], 16)) % n)[2:], 64)
    else:
        p1 = public_key_to_point(decompress_public_key(parent_public_key))
        p2 = public_key_to_point(get_public_key(hash[:64]))
        child_point = elliptic_curve.add(p1, p2, p)
        child_key = compress_public_key(point_to_public_key(child_point))
    child_chain_code = hash[64:]

    return f'{child_chain_code}{child_key}'


def encode_extended_key(extended_key: str, version: str = 'private', depth: str or int = 0, index: str or int = 0, parent_public_key: str = None) -> str:

    index = str(index)
    depth = str(depth)

    if index[len(index) - 1] == "'":
        index = int(index[0:len(index) - 1], 10) + 2 ** 31
    else:
        index = int(index, 10)
    index = hex(index)[2:]

    key = extended_key[64:]
    chain_code = extended_key[:64]

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
        parent_fingerprint = hash160(hex_to_bytes(parent_public_key)).digest()[:4]

    extended_key_bytes = hex_to_bytes(str(depth)) + parent_fingerprint + hex_to_bytes(index, min_num_of_bytes=4) + hex_to_bytes(chain_code) + hex_to_bytes(key)

    return encode_base58check(extended_key_bytes, version_code)


def parse_extended_key(extended_key: str) -> dict:
    return {'key': extended_key[64:], 'chain_code': extended_key[:64]}


def generate_extended_key_from_derivation_path(seed: str, derivation_path: str) -> str:

    derivation_path_list = derivation_path.split('/')

    if derivation_path_list[0] == 'm':
        pass
    elif derivation_path_list[0] == 'M':
        pass
    else:
        raise Exception('First character of derivation path need to be m or M')

    last_extended_private_key = generate_master_private_key(seed)
    for index in derivation_path_list[1:]:
        last_extended_private_key = generate_child_extended_key(last_extended_private_key, index)
    return last_extended_private_key


def get_extended_public_key(extended_private_key: str) -> str:
    return parse_extended_key(extended_private_key)['chain_code'] + get_compressed_public_key(parse_extended_key(extended_private_key)['key'])


def generate_extended_key_bip44(master_extended_private_key: str, coin: int or str = "0'", account: int or str = "0'", internal_external: int or str = "0", address: int or str = "0"):
    coin = str(coin)
    account = str(account)
    internal_external = str(internal_external)
    address = str(address)

    purpose_extended_private_key = generate_child_extended_key(master_extended_private_key, "44'")
    coin_extended_private_key = generate_child_extended_key(purpose_extended_private_key, coin)
    account_extended_private_key = generate_child_extended_key(coin_extended_private_key, account)
    internal_external_extended_private_key = generate_child_extended_key(account_extended_private_key, internal_external)
    address_extended_private_key = generate_child_extended_key(internal_external_extended_private_key, address)

    return address_extended_private_key
