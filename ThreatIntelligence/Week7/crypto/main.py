import base64
import hashlib
import binascii

from Cryptodome.Cipher import DES, DES3, AES
from Cryptodome.Util.Padding import pad, unpad

plaintext = "Omar&2023@_"
key = "infolab"

def hash_md5(plaintext):
    hash_object = hashlib.md5(plaintext.encode())         # Create an MD5 hash object
    return hash_object.hexdigest()                        # Get the hashed value


def hash_sha1(plaintext):
    hash_object = hashlib.sha1(plaintext.encode())        # Create a SHA-1 hash object
    return hash_object.hexdigest()                        # Get the hashed value


def hash_sha256(plaintext):
    hash_object = hashlib.sha256(plaintext.encode())      # Create a SHA-256 hash object
    return hash_object.hexdigest()                        # Get the hashed value


def encrypt_des(plaintext, key):
    key = key[:8].ljust(8, '\0')
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext.decode('utf-8')
    """key = key[:8].ljust(8, " ")
    key_bytes = key.encode("utf-8")
    plaintext_bytes = plaintext.encode("utf-8")
    
    cipher = DES.new(key_bytes, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, DES.block_size))
    encoded_ciphertext = binascii.hexlify(ciphertext).decode("utf-8")
    return encoded_ciphertext"""


def decrypt_des(encodedtext, key):
    key = key[:8].ljust(8, " ")
    key_bytes = key.encode("utf-8")
    decoded_ciphertext = binascii.unhexlify(encodedtext)
    decipher = DES.new(key_bytes, DES.MODE_ECB)
    decrypted_plaintext = unpad(decipher.decrypt(decoded_ciphertext), DES.block_size).decode("utf-8")
    return decrypted_plaintext


def encrypt_3des(plaintext, key):
    key = key[:24].ljust(24, " ")
    key_bytes = key.encode("utf-8")
    plaintext_bytes = plaintext.encode("utf-8")

    cipher = DES3.new(key_bytes, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, DES3.block_size))
    encoded_ciphertext = base64.b64encode(ciphertext).decode("utf-8")
    return encoded_ciphertext


def decrypt_3des(encodedtext, key):
    key = key[:24].ljust(24, " ")
    key_bytes = key.encode("utf-8")
    decoded_ciphertext = base64.b64decode(encodedtext)
    decipher = DES3.new(key_bytes, DES3.MODE_ECB)
    decrypted_plaintext = unpad(decipher.decrypt(decoded_ciphertext), DES3.block_size).decode("utf-8")
    return decrypted_plaintext


def encrypt_aes(plaintext, key):
    key = key[:16].ljust(16, " ")
    key_bytes = key.encode("utf-8")
    plaintext_bytes = plaintext.encode("utf-8")

    cipher = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    encoded_ciphertext = binascii.hexlify(ciphertext).decode("utf-8")
    return encoded_ciphertext


def decrypt_aes(encodedtext, key):
    key = key[:16].ljust(16, " ")
    key_bytes = key.encode("utf-8")
    decoded_ciphertext = binascii.unhexlify(encodedtext)
    decipher = AES.new(key_bytes, AES.MODE_ECB)
    decrypted_plaintext = unpad(decipher.decrypt(decoded_ciphertext), AES.block_size).decode("utf-8")
    return decrypted_plaintext


def encode_base64(plaintext):
    plaintext_bytes = plaintext.encode("utf-8")
    encoded_bytes = base64.b64encode(plaintext_bytes)
    encoded_text = encoded_bytes.decode("utf-8")
    return encoded_text


def encode_utf8(plaintext):
    encoded_string = plaintext.encode("utf-8")
    result = ""
    for char in encoded_string:
        if char == 32:  # ASCII code for space character
            result += "+"
        elif (char >= 48 and char <= 57) or (char >= 65 and char <= 90) or (char >= 97 and char <= 122) or char == 45 or char == 46 or char == 95 or char == 126:
            result += chr(char)
        else:
            result += "%{:02X}".format(char)
    return result


print(f"Plaintext : {plaintext}")
print(f"Key : {key}")
print(f"Hashing [MD5]: {hash_md5(plaintext)} ({len(hash_md5(plaintext))})")
print(f"Hashing [SHA-1]: {hash_sha1(plaintext)} ({len(hash_sha1(plaintext))})")
print(f"Hashing [SHA-256]: {hash_sha256(plaintext)} ({len(hash_sha256(plaintext))})")
"""
print(f"Encrypt [DES]: {encrypt_des(plaintext, key)} ({len(encrypt_des(plaintext, key))})")
print(f"Decrypt [DES]: {decrypt_des(encrypt_des(plaintext, key), key)} ({len(decrypt_des(encrypt_des(plaintext, key), key))})")
print(f"Encrypt [3DES]: {encrypt_3des(plaintext, key)}")
print(f"Decrypt [3DES]: {decrypt_3des(encrypt_3des(plaintext, key), key)}")
"""
print(f"Encrypt [AES]: {encrypt_aes(plaintext, key)} ({len(encrypt_aes(plaintext, key))})")
print(f"Decrypt [AES]: {decrypt_aes(encrypt_aes(plaintext, key), key)} ({len(decrypt_aes(encrypt_aes(plaintext, key), key))})")
print(f"Encoding [Base64]: {encode_base64(plaintext)} ({len(encode_base64(plaintext))})")
print(f"Encoding [UTF-8]: {encode_utf8(plaintext)} ({len(encode_utf8(plaintext))})")
