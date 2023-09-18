import hashlib

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


print(f"Plaintext : {plaintext}")
print(f"Key : {key}")
print(f"Hashing [MD5]: {hash_md5(plaintext)} ({len(hash_md5(plaintext))})")
print(f"Hashing [SHA-1]: {hash_sha1(plaintext)} ({len(hash_sha1(plaintext))})")
print(f"Hashing [SHA-256]: {hash_sha256(plaintext)} ({len(hash_sha256(plaintext))})")