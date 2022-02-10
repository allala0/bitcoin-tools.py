import bitcoin_tools


def example():
    private_key = bitcoin_tools.generate_random_private_key()
    print(f'Private key: {private_key}')

    encoded_private_key = bitcoin_tools.encode_private_key(private_key)
    print(f'Encoded private key: {encoded_private_key}')

    decoded_private_key = bitcoin_tools.decode_private_key(encoded_private_key)
    print(f'Decoded private key: {decoded_private_key}')

    compressed_private_key = bitcoin_tools.compress_private_key(decoded_private_key)
    print(f'Compressed private key: {compressed_private_key}')

    encoded_compressed_private_key = bitcoin_tools.encode_private_key(compressed_private_key)
    print(f'Encoded compressed private key: {encoded_compressed_private_key}')

    decoded_compressed_private_key = bitcoin_tools.decode_private_key(encoded_compressed_private_key)
    print(f'Decoded compressed private key: {decoded_compressed_private_key}')

    public_key = bitcoin_tools.get_public_key(private_key)
    print(f'Public key: {public_key}')

    compressed_public_key = bitcoin_tools.compress_public_key(public_key)
    print(f'Compressed public key: {compressed_public_key}')

    decompressed_public_key = bitcoin_tools.decompress_public_key(compressed_public_key)
    print(f'Decompressed public key: {decompressed_public_key}')

    compressed_address = bitcoin_tools.get_address(compressed_public_key)
    print(f'Compressed address: {compressed_address}')

    encoded_compressed_address = bitcoin_tools.encode_address(compressed_address)
    print(f'Encoded compressed address: {encoded_compressed_address}')

    decoded_compressed_address = bitcoin_tools.decode_address(encoded_compressed_address)
    print(f'Decoded compressed address: {decoded_compressed_address}')

    decompressed_address = bitcoin_tools.get_address(decompressed_public_key)
    print(f'Decompressed address: {decompressed_address}')

    encoded_decompressed_address = bitcoin_tools.encode_address(decompressed_address)
    print(f'Encoded decompressed address: {encoded_decompressed_address}')

    decoded_decompressed_address = bitcoin_tools.decode_address(encoded_decompressed_address)
    print(f'Decoded decompressed address: {decoded_decompressed_address}')

    print()

    mnemonic = bitcoin_tools.generate_mnemonic(12)
    # mnemonic = 'army van defense carry jealous true garbage claim echo media make crunch'
    print(f'Mnemonic: {mnemonic}')

    master_seed = bitcoin_tools.get_seed(mnemonic)
    print(f'Seed: {master_seed}')

    master_extended_private_key = bitcoin_tools.generate_master_private_key(master_seed)
    print(f'Master extended private key: {master_extended_private_key}')

    master_extended_public_key = bitcoin_tools.get_extended_public_key(master_extended_private_key)
    print(f'Master extended private key: {master_extended_public_key}')

    encoded_master_extended_private_key = bitcoin_tools.encode_extended_key(master_extended_private_key)
    print(f'Master Encoded extended private key: {encoded_master_extended_private_key}')

    encoded_master_extended_public_key = bitcoin_tools.encode_extended_key(master_extended_public_key, version='public')
    print(f'Master encoded extended public key: {encoded_master_extended_public_key}')

    child_extended_private_key = bitcoin_tools.generate_child_extended_key(master_extended_private_key, "0")
    print(f'Child extended private key: {child_extended_private_key}')

    child_extended_public_key = bitcoin_tools.get_extended_public_key(child_extended_private_key)
    print(f'Child extended public key: {child_extended_public_key}')

    child_extended_public_key_from_public_key = bitcoin_tools.generate_child_extended_key(master_extended_public_key, "0", version='public')
    print(f'Child extended public key from public key: {child_extended_public_key_from_public_key}')

    child_encoded_extended_private_key = bitcoin_tools.encode_extended_key(child_extended_private_key, depth=1, index="0", parent_public_key=bitcoin_tools.parse_extended_key(master_extended_public_key)['key'])
    print(f'Child encoded extended private key: {child_encoded_extended_private_key}')

    child_encoded_extended_public_key = bitcoin_tools.encode_extended_key(child_extended_public_key, depth=1, index="0", parent_public_key=bitcoin_tools.parse_extended_key(master_extended_public_key)['key'], version='public')
    print(f'Child encoded extended public key: {child_encoded_extended_public_key}')

    print()

    extended_private_key_from_bip44 = bitcoin_tools.generate_extended_key_bip44(master_extended_private_key, address=1)
    print(f'Extended private key generated from bip44: {extended_private_key_from_bip44}')

    extended_private_key_from_derivation_path = bitcoin_tools.generate_extended_key_from_derivation_path(master_seed, "m/44'/0'/0'/0/0")
    print(f'Extended private key from derivation path: {extended_private_key_from_derivation_path}')

    print()

    vanity_address = bitcoin_tools.generate_vanity_address('1', any_case=True)
    print(f'Vanity address: {vanity_address}')


if __name__ == '__main__':
    example()
