import bitcoin_tools

private_key = bitcoin_tools.get_random_private_key()
print(f'Private key: {private_key}')

encoded_private_key = bitcoin_tools.encode_private_key(private_key)
print(f'Encoded private key: {encoded_private_key}')

decoded_private_key = bitcoin_tools.decode_private_key(encoded_private_key)
print(f'Decoded private key: {decoded_private_key}')

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
