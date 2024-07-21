from PIL import Image
import struct

# TEA encryption function
def enc_ta(plain_text, key):
    delta = 0x9e3779b9
    sum = 0
    n = 32
    left, right = struct.unpack('>2L', plain_text)
    for _ in range(n):
        sum = (sum + delta) & 0xFFFFFFFF
        left = (left + (((right << 4) + key[0]) ^ (right + sum) ^ ((right >> 5) + key[1]))) & 0xFFFFFFFF
        right = (right + (((left << 4) + key[2]) ^ (left + sum) ^ ((left >> 5) + key[3]))) & 0xFFFFFFFF
    cipher_text = struct.pack('>2L', left, right)
    return cipher_text

# TEA decryption function
def dec_ta(cipher_text, key):
    delta = 0x9e3779b9
    n = 32
    sum = (delta * 32) & 0xFFFFFFFF
    left, right = struct.unpack('>2L', cipher_text)
    for _ in range(n):
        right = (right - (((left << 4) + key[2]) ^ (left + sum) ^ ((left >> 5) + key[3]))) & 0xFFFFFFFF
        left = (left - (((right << 4) + key[0]) ^ (right + sum) ^ ((right >> 5) + key[1]))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF
    plain_text = struct.pack('>2L', left, right)
    return plain_text

# TEA CBC encryption function
def enc_ta_cbc(plain_text, key, iv):
    delta = 0x9e3779b9
    sum = 0
    n = 32
    left, right = struct.unpack('>2L', plain_text)
    iv_left, iv_right = iv
    left = left ^ iv_left
    right = right ^ iv_right
    for _ in range(n):
        sum = (sum + delta) & 0xFFFFFFFF
        left = (left + (((right << 4) + key[0]) ^ (right + sum) ^ ((right >> 5) + key[1]))) & 0xFFFFFFFF
        right = (right + (((left << 4) + key[2]) ^ (left + sum) ^ ((left >> 5) + key[3]))) & 0xFFFFFFFF
    cipher_text = struct.pack('>2L', left, right)
    return cipher_text
# TEA CBC decryption function
def dec_ta_cbc(cipher_text, key, iv):
    delta = 0x9e3779b9
    n = 32
    sum = (delta * 32) & 0xFFFFFFFF
    left, right = struct.unpack('>2L', cipher_text)
    iv_left, iv_right = iv
    for _ in range(n):
        right = (right - (((left << 4) + key[2]) ^ (left + sum) ^ ((left >> 5) + key[3]))) & 0xFFFFFFFF
        left = (left - (((right << 4) + key[0]) ^ (right + sum) ^ ((right >> 5) + key[1]))) & 0xFFFFFFFF
        sum = (sum - delta) & 0xFFFFFFFF
    left = left ^ iv_left
    right = right ^ iv_right
    plain_text = struct.pack('>2L', left, right)
    return plain_text

# Convert image data to blocks
def convert_to_data(image_path):
    img = Image.open(image_path)
    img = img.convert('L')  # Convert to grayscale mode
    pixels = img.tobytes()  # Get pixel intensity values
    size = 8
    block_group_pixels = [pixels[i:i + size] for i in range(0, len(pixels), size)]
    return block_group_pixels, img.size

# Convert blocks back to image data
def convert_to_image(pixels, size, output_path):
    img = Image.new('L', size)
    img.putdata(pixels)
    img.save(output_path)

# Encrypt image blocks using TEA-ECB
def enc_image(blocks, key):
    enc_blocks = []
    for i, block in enumerate(blocks):
        if i < 10:  # Leave the first 10 blocks unencrypted
            enc_blocks.append(block)
        else:
            enc_block = enc_ta(block, key)
            enc_blocks.append(enc_block)
    return enc_blocks

# Decrypt image blocks using TEA-ECB
def dec_images(enc_blocks, key):
    dec_blocks = []
    for i, block in enumerate(enc_blocks):
        if i < 10:  # Leave the first 10 blocks unencrypted
            dec_blocks.append(block)
        else:
            dec_block = dec_ta(block, key)
            dec_blocks.append(dec_block)
    return dec_blocks

# Encrypt image blocks using TEA-CBC
def enc_image_cbc(blocks, key, iv):
    enc_blocks = []
    for i, block in enumerate(blocks):
        if i < 10:  # Leave the first 10 blocks unencrypted
            enc_blocks.append(block)
        else:
            enc_block = enc_ta_cbc(block, key, iv)
            enc_blocks.append(enc_block)
            iv = struct.unpack('>2L', enc_block)
    return enc_blocks

# Decrypt image blocks using TEA-CBC
def dec_images_cbc(enc_blocks, key, iv):
    dec_blocks = []
    for i, block in enumerate(enc_blocks):
        if i < 10:  # Leave the first 10 blocks unencrypted
            dec_blocks.append(block)
        else:
            dec_block = dec_ta_cbc(block, key, iv)
            dec_blocks.append(dec_block)
            iv = struct.unpack('>2L', block)
    return dec_blocks


def main():
    key = b'\xAA\xBB\xCC\xDD\xEE\xFF\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99'
    iv = b'\xFF\xEE\xDD\xCC\xBB\xAA\x99\x88'
    input_path = 'Aqsa.bmp'
    output_path_ecb = 'encrypt_image_ecb.bmp'
    output_path_cbc = 'encrypt_image_cbc.bmp'
    decrypted_output_path_ecb = 'decrypt_image_ecb.bmp'
    decrypted_output_path_cbc = 'decrypt_image_cbc.bmp'

    if len(key) != 16:
        raise ValueError("Key length should be 128 bits (16 bytes)")
    if len(iv) != 8:
        raise ValueError("IV length should be 64 bits (8 bytes)")

    key_tuple = struct.unpack('>4L', key)
    iv_tuple = struct.unpack('>2L', iv)

    # Encrypt using ECB
    blocks, size = convert_to_data(input_path)
    encrypted_blocks_ecb = enc_image(blocks, key_tuple)
    encrypted_blocks_list_ecb = b''.join(encrypted_blocks_ecb)
    encrypted_image_ecb = Image.frombytes('L', size, encrypted_blocks_list_ecb)
    encrypted_image_ecb.save(output_path_ecb)

    # Decrypt using ECB
    decrypted_blocks_ecb = dec_images(encrypted_blocks_ecb, key_tuple)
    decrypted_blocks_list_ecb = b''.join(decrypted_blocks_ecb)
    decrypted_image_ecb = Image.frombytes('L', size, decrypted_blocks_list_ecb)
    decrypted_image_ecb.save(decrypted_output_path_ecb)

    # Encrypt using CBC
    encrypted_blocks_cbc = enc_image_cbc(blocks, key_tuple, iv_tuple)
    encrypted_blocks_list_cbc = b''.join(encrypted_blocks_cbc)
    encrypted_image_cbc = Image.frombytes('L', size, encrypted_blocks_list_cbc)
    encrypted_image_cbc.save(output_path_cbc)

    # Decrypt using CBC
    decrypted_blocks_cbc = dec_images_cbc(encrypted_blocks_cbc, key_tuple, iv_tuple)
    decrypted_blocks_list_cbc = b''.join(decrypted_blocks_cbc)
    decrypted_image_cbc = Image.frombytes('L', size, decrypted_blocks_list_cbc)
    decrypted_image_cbc.save(decrypted_output_path_cbc)

if __name__ == '__main__':
    main()
