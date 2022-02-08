import bitcoin_tools


def test():
    private_key = bitcoin_tools.get_random_private_key()
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

    mnemonic = bitcoin_tools.generate_mnemonic(12)
    mnemonic = 'army van defense carry jealous true garbage claim echo media make crunch'
    print(f'Mnemonic: {mnemonic}')

    root_seed = bitcoin_tools.generate_seed(mnemonic, passphrase='')
    print(f'Seed: {root_seed}')

    master_extended_private_key = bitcoin_tools.generate_master_private_key(root_seed)
    print(f'Master extended private key: {master_extended_private_key}')

    encoded_master_extended_key = bitcoin_tools.encode_extended_key('private',  master_extended_private_key['private_key'], master_extended_private_key['chain_code'], 0, 0)
    print(f'Encoded extended master private key: {encoded_master_extended_key}')

    encoded_master_extended_key = bitcoin_tools.encode_extended_key('public',  bitcoin_tools.get_compressed_public_key(master_extended_private_key['private_key']), master_extended_private_key['chain_code'], 0, 0)
    print(f'Encoded extended master public key: {encoded_master_extended_key}')

    child_extended_private_key = bitcoin_tools.generate_child_extended_key('private', master_extended_private_key['private_key'], master_extended_private_key['chain_code'], "2137'")
    print(f'Child extended private key: {child_extended_private_key}')

    grandchild_extended_private_key = bitcoin_tools.generate_child_extended_key('private', child_extended_private_key['private_key'], child_extended_private_key['chain_code'], "11")
    print(f'Grandchild extended private key: {grandchild_extended_private_key}')

    print(bitcoin_tools.get_compressed_public_key(grandchild_extended_private_key['private_key']))

    # vanity_address = bitcoin_tools.generate_vanity_address('x', any_case=True)
    # print(f'Vanity address: {vanity_address}')



test()
